/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2026, librdkafka contributors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * librdkafka - private Windows Schannel TLS adapter.
 * Distributed under the project's BSD-2-Clause license.
 */
#include "rdkafka_int.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_tls.h"
#include "rdkafka_cert.h"
#include "rdkafka_schannel.h"

#if WITH_SCHANNEL
#define RD_SCHANNEL_BUFFER_SIZE (64 * 1024)
#define RD_SCHANNEL_FILE_LIMIT  (16 * 1024 * 1024)
#define RD_SCHANNEL_PLAIN_CHUNK (16 * 1024)

typedef struct rd_kafka_schannel_config_s {
        CredHandle cred;
        rd_bool_t have_cred;
        HCERTSTORE roots;
        HCERTCHAINENGINE engine;
        HCERTSTORE identity_store;
        PCCERT_CONTEXT identity;
        NCRYPT_PROV_HANDLE provider;
        NCRYPT_KEY_HANDLE key;
        rd_bool_t own_key;
} rd_kafka_schannel_config_t;

typedef struct rd_kafka_schannel_session_s {
        CtxtHandle context;
        rd_bool_t have_context;
        rd_bool_t handshake_done;
        rd_bool_t verified;
        rd_bool_t need_read;
        rd_bool_t input_incomplete;
        rd_bool_t eof;
        WCHAR hostname[RD_KAFKA_NODENAME_SIZE];
        SecPkgContext_StreamSizes sizes;
        unsigned char input[RD_SCHANNEL_BUFFER_SIZE];
        size_t input_len;
        unsigned char output[RD_SCHANNEL_BUFFER_SIZE];
        size_t output_len;
        size_t output_of;
        unsigned char plaintext[RD_SCHANNEL_BUFFER_SIZE];
        size_t plaintext_len;
        size_t plaintext_of;
        const rd_buf_t *pending_buf;
        size_t pending_offset;
        size_t pending_n;
        ULONG attributes;
} rd_kafka_schannel_session_t;

static void rd_kafka_schannel_error(char *errstr,
                                    size_t size,
                                    const char *operation,
                                    unsigned long status) {
        rd_snprintf(errstr, size, "Schannel %s failed (0x%08lx)", operation,
                    status);
}

static int rd_kafka_schannel_copy_store(HCERTSTORE dest,
                                        HCERTSTORE src,
                                        PCCERT_CONTEXT *first) {
        PCCERT_CONTEXT cert = NULL;
        int count           = 0;
        while ((cert = CertEnumCertificatesInStore(src, cert))) {
                PCCERT_CONTEXT added = NULL;
                if (!CertAddCertificateContextToStore(
                        dest, cert, CERT_STORE_ADD_ALWAYS, &added)) {
                        CertFreeCertificateContext(cert);
                        return -1;
                }
                if (!count && first)
                        *first = CertDuplicateCertificateContext(added);
                CertFreeCertificateContext(added);
                count++;
        }
        return count;
}

static int rd_kafka_schannel_read_certs(HCERTSTORE store,
                                        const char *path,
                                        const char *pem,
                                        PCCERT_CONTEXT *first,
                                        char *errstr,
                                        size_t errstr_size) {
        char *file = NULL;
        size_t size;
        int ret;
        if (pem)
                size = strlen(pem);
        else {
                file = rd_file_read(path, &size, RD_SCHANNEL_FILE_LIMIT);
                if (!file) {
                        rd_snprintf(errstr, errstr_size,
                                    "Schannel could not read certificate file "
                                    "(max 16 MiB)");
                        return -1;
                }
                pem = file;
        }
        ret =
            rd_kafka_schannel_add_certs(store, pem, size, RD_KAFKA_CERT_ENC_PEM,
                                        first, errstr, errstr_size);
        rd_free(file);
        return ret;
}

static void rd_kafka_schannel_config_free(rd_kafka_schannel_config_t *cfg) {
        if (!cfg)
                return;
        if (cfg->have_cred)
                FreeCredentialsHandle(&cfg->cred);
        if (cfg->identity)
                CertFreeCertificateContext(cfg->identity);
        if (cfg->identity_store)
                CertCloseStore(cfg->identity_store, 0);
        if (cfg->own_key && cfg->key)
                NCryptFreeObject(cfg->key);
        if (cfg->own_key && cfg->provider)
                NCryptFreeObject(cfg->provider);
        if (cfg->engine)
                CertFreeCertificateChainEngine(cfg->engine);
        if (cfg->roots)
                CertCloseStore(cfg->roots, 0);
        rd_free(cfg);
}

static int rd_kafka_schannel_validate_options(rd_kafka_t *rk,
                                              char *errstr,
                                              size_t errstr_size) {
        const char *options[] = {
            "ssl.cipher.suites",         "ssl.curves.list",
            "ssl.sigalgs.list",          "ssl.providers",
            "ssl.engine.location",       "ssl.engine.id",
            "ssl.key.password",          "ssl.crl.location",
            "ssl.ca.certificate.stores", NULL};
        const char **option;
        rd_kafka_conf_t *c = &rk->rk_conf;
        for (option = options; *option; option++) {
                if (rd_kafka_conf_is_modified(c, *option)) {
                        rd_snprintf(errstr, errstr_size,
                                    "%s is unsupported by Schannel", *option);
                        return -1;
                }
        }
        if (c->ssl.cert_verify_cb || c->ssl.engine_callback_data) {
                rd_snprintf(errstr, errstr_size,
                            "OpenSSL certificate/engine callbacks are "
                            "unsupported by Schannel");
                return -1;
        }
        if (!c->ssl.enable_verify ||
            c->ssl.endpoint_identification != RD_KAFKA_SSL_ENDPOINT_ID_HTTPS) {
                rd_snprintf(
                    errstr, errstr_size,
                    "Schannel requires certificate and hostname verification");
                return -1;
        }
        if ((!!c->ssl.ca + !!c->ssl.ca_pem + !!c->ssl.ca_location) > 1 ||
            (!!c->ssl.cert + !!c->ssl.cert_pem + !!c->ssl.cert_location) > 1 ||
            (!!c->ssl.key + !!c->ssl.key_pem + !!c->ssl.key_location) > 1) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel requires one source for each CA, "
                            "certificate and private key");
                return -1;
        }
        if (c->ssl.ca_location && !strcmp(c->ssl.ca_location, "probe")) {
                rd_snprintf(errstr, errstr_size,
                            "ssl.ca.location=probe is unsupported by Schannel; "
                            "leave unset for system trust");
                return -1;
        }
        if (c->ssl.keystore_location &&
            (c->ssl.cert || c->ssl.cert_pem || c->ssl.cert_location ||
             c->ssl.key || c->ssl.key_pem || c->ssl.key_location)) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel keystore and separate certificate/key "
                            "sources are mutually exclusive");
                return -1;
        }
        return 0;
}

/* Bind a separate ephemeral key to a per-client certificate copy. Never mutate
 * a refcounted certificate belonging to the public configuration setter. */
static int rd_kafka_schannel_bind_key(rd_kafka_schannel_config_t *cfg,
                                      char *errstr,
                                      size_t errstr_size) {
        CERT_KEY_CONTEXT keyctx;
        CERT_PUBLIC_KEY_INFO *public_key = NULL;
        DWORD size                       = 0;
        if (!CryptExportPublicKeyInfo((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)cfg->key,
                                      CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING,
                                      NULL, &size))
                goto fail;
        public_key = rd_malloc(size);
        if (!CryptExportPublicKeyInfo((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)cfg->key,
                                      CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING,
                                      public_key, &size) ||
            !CertComparePublicKeyInfo(
                X509_ASN_ENCODING, public_key,
                &cfg->identity->pCertInfo->SubjectPublicKeyInfo))
                goto fail;
        rd_free(public_key);
        memset(&keyctx, 0, sizeof(keyctx));
        keyctx.cbSize     = sizeof(keyctx);
        keyctx.hNCryptKey = cfg->key;
        keyctx.dwKeySpec  = CERT_NCRYPT_KEY_SPEC;
        if (!CertSetCertificateContextProperty(
                cfg->identity, CERT_KEY_CONTEXT_PROP_ID,
                CERT_STORE_NO_CRYPT_RELEASE_FLAG, &keyctx))
                goto fail_no_public;
        return 0;
fail:
        rd_free(public_key);
fail_no_public:
        rd_snprintf(errstr, errstr_size,
                    "Schannel certificate/private key mismatch or binding "
                    "failed (0x%08lx)",
                    (unsigned long)GetLastError());
        return -1;
}

static int
rd_kafka_schannel_ctx_init(rd_kafka_t *rk, char *errstr, size_t errstr_size) {
        rd_kafka_conf_t *conf           = &rk->rk_conf;
        rd_kafka_schannel_config_t *cfg = NULL;
        SCHANNEL_CRED credentials;
        SECURITY_STATUS status;
        TimeStamp expiry;
        if (rd_kafka_schannel_validate_options(rk, errstr, errstr_size) == -1)
                return -1;
        cfg = rd_calloc(1, sizeof(*cfg));
        SecInvalidateHandle(&cfg->cred);
        if (conf->ssl.ca || conf->ssl.ca_pem || conf->ssl.ca_location) {
                CERT_CHAIN_ENGINE_CONFIG engine;
                cfg->roots =
                    CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
                if (!cfg->roots)
                        goto win_error;
                if (conf->ssl.ca) {
                        if (rd_kafka_schannel_copy_store(
                                cfg->roots, conf->ssl.ca->win_store, NULL) <= 0)
                                goto win_error;
                } else if (rd_kafka_schannel_read_certs(
                               cfg->roots, conf->ssl.ca_location,
                               conf->ssl.ca_pem, NULL, errstr,
                               errstr_size) == -1)
                        goto fail;
                memset(&engine, 0, sizeof(engine));
                engine.cbSize         = sizeof(engine);
                engine.hExclusiveRoot = cfg->roots;
                engine.dwFlags        = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
#ifdef CERT_CHAIN_DISABLE_AIA
                engine.dwFlags |= CERT_CHAIN_DISABLE_AIA;
#endif
                engine.dwUrlRetrievalTimeout = 1000;
                if (!CertCreateCertificateChainEngine(&engine, &cfg->engine))
                        goto win_error;
        }
        if (conf->ssl.keystore_location) {
                size_t file_size;
                char *file      = rd_file_read(conf->ssl.keystore_location,
                                               &file_size, RD_SCHANNEL_FILE_LIMIT);
                WCHAR *password = NULL;
                CRYPT_DATA_BLOB blob;
                PCCERT_CONTEXT cert = NULL;
                int count;
                if (!file) {
                        rd_snprintf(errstr, errstr_size,
                                    "Schannel could not read PKCS#12 keystore");
                        goto fail;
                }
                count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            conf->ssl.keystore_password
                                                ? conf->ssl.keystore_password
                                                : "",
                                            -1, NULL, 0);
                if (!count) {
                        SecureZeroMemory(file, file_size);
                        rd_free(file);
                        goto win_error;
                }
                password = rd_calloc((size_t)count, sizeof(*password));
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    conf->ssl.keystore_password
                                        ? conf->ssl.keystore_password
                                        : "",
                                    -1, password, count);
                blob.pbData         = (BYTE *)file;
                blob.cbData         = (DWORD)file_size;
                cfg->identity_store = PFXImportCertStore(
                    &blob, password,
                    PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY);
                SecureZeroMemory(password, (size_t)count * sizeof(*password));
                rd_free(password);
                SecureZeroMemory(file, file_size);
                rd_free(file);
                if (!cfg->identity_store)
                        goto win_error;
                while ((cert = CertEnumCertificatesInStore(cfg->identity_store,
                                                           cert))) {
                        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key;
                        DWORD spec;
                        BOOL free_key;
                        if (CryptAcquireCertificatePrivateKey(
                                cert,
                                CRYPT_ACQUIRE_SILENT_FLAG |
                                    CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                                NULL, &key, &spec, &free_key)) {
                                if (spec != CERT_NCRYPT_KEY_SPEC) {
                                        if (free_key)
                                                CryptReleaseContext(
                                                    (HCRYPTPROV)key, 0);
                                        CertFreeCertificateContext(cert);
                                        rd_snprintf(
                                            errstr, errstr_size,
                                            "Schannel PKCS#12 identity "
                                            "requires a CNG private key");
                                        goto fail;
                                }
                                if (free_key) {
                                        cfg->key     = (NCRYPT_KEY_HANDLE)key;
                                        cfg->own_key = rd_true;
                                }
                                cfg->identity =
                                    CertDuplicateCertificateContext(cert);
                                CertFreeCertificateContext(cert);
                                break;
                        }
                }
                if (!cfg->identity) {
                        rd_snprintf(errstr, errstr_size,
                                    "Schannel PKCS#12 keystore has no usable "
                                    "private-key identity");
                        goto fail;
                }
                if (cfg->own_key &&
                    rd_kafka_schannel_bind_key(cfg, errstr, errstr_size) == -1)
                        goto fail;
        } else if (conf->ssl.cert || conf->ssl.cert_location ||
                   conf->ssl.cert_pem || conf->ssl.key ||
                   conf->ssl.key_location || conf->ssl.key_pem) {
                const void *key_data;
                size_t key_size;
                char *key_file = NULL;
                cfg->identity_store =
                    CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
                if (!cfg->identity_store)
                        goto win_error;
                if (conf->ssl.cert) {
                        if (rd_kafka_schannel_copy_store(
                                cfg->identity_store, conf->ssl.cert->win_store,
                                &cfg->identity) <= 0)
                                goto win_error;
                } else if (conf->ssl.cert_location || conf->ssl.cert_pem) {
                        if (rd_kafka_schannel_read_certs(
                                cfg->identity_store, conf->ssl.cert_location,
                                conf->ssl.cert_pem, &cfg->identity, errstr,
                                errstr_size) == -1)
                                goto fail;
                }
                if (!cfg->identity) {
                        rd_snprintf(errstr, errstr_size,
                                    "Schannel client private key requires its "
                                    "certificate");
                        goto fail;
                }
                if (conf->ssl.key) {
                        cfg->key = (NCRYPT_KEY_HANDLE)conf->ssl.key->win_key;
                        cfg->provider =
                            (NCRYPT_PROV_HANDLE)conf->ssl.key->win_provider;
                } else {
                        if (conf->ssl.key_pem) {
                                key_data = conf->ssl.key_pem;
                                key_size = strlen(key_data);
                        } else if (conf->ssl.key_location) {
                                key_file = rd_file_read(conf->ssl.key_location,
                                                        &key_size,
                                                        RD_SCHANNEL_FILE_LIMIT);
                                key_data = key_file;
                                if (!key_file) {
                                        rd_snprintf(errstr, errstr_size,
                                                    "Schannel could not read "
                                                    "client private key");
                                        goto fail;
                                }
                        } else {
                                rd_snprintf(
                                    errstr, errstr_size,
                                    "Schannel client certificate requires an "
                                    "unencrypted PKCS#8 private key");
                                goto fail;
                        }
                        cfg->own_key = rd_true;
                        status       = rd_kafka_schannel_import_key(
                            key_data, key_size, RD_KAFKA_CERT_ENC_PEM,
                            &cfg->provider, &cfg->key, errstr, errstr_size);
                        if (key_file) {
                                SecureZeroMemory(key_file, key_size);
                                rd_free(key_file);
                        }
                        if (status == -1)
                                goto fail;
                }
                if (rd_kafka_schannel_bind_key(cfg, errstr, errstr_size) == -1)
                        goto fail;
        }
        memset(&credentials, 0, sizeof(credentials));
        credentials.dwVersion             = SCHANNEL_CRED_VERSION;
        credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
        credentials.dwFlags =
            SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
#ifdef SCH_USE_STRONG_CRYPTO
        credentials.dwFlags |= SCH_USE_STRONG_CRYPTO;
#endif
        if (cfg->identity) {
                credentials.cCreds = 1;
                credentials.paCred = &cfg->identity;
        }
        status = AcquireCredentialsHandleA(
            NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &credentials, NULL,
            NULL, &cfg->cred, &expiry);
        if (status != SEC_E_OK) {
                rd_kafka_schannel_error(errstr, errstr_size,
                                        "credential acquisition",
                                        (unsigned long)status);
                goto fail;
        }
        cfg->have_cred    = rd_true;
        conf->ssl.tls_ctx = cfg;
        rd_kafka_dbg(rk, SECURITY, "TLSBACKEND",
                     "Broker TLS backend Schannel (TLS 1.2, verified server "
                     "identity); crypto module qualification is external");
        return 0;
win_error:
        rd_kafka_schannel_error(errstr, errstr_size,
                                "certificate configuration", GetLastError());
fail:
        rd_kafka_schannel_config_free(cfg);
        return -1;
}

static void rd_kafka_schannel_ctx_term(rd_kafka_t *rk) {
        rd_kafka_schannel_config_free(rk->rk_conf.ssl.tls_ctx);
        rk->rk_conf.ssl.tls_ctx = NULL;
}

static int rd_kafka_schannel_interests(rd_kafka_transport_t *t) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        return POLLIN | ((s->output_of < s->output_len || s->pending_n ||
                          (!s->verified && s->input_len && !s->need_read))
                             ? POLLOUT
                             : 0);
}
static void rd_kafka_schannel_update(rd_kafka_transport_t *t) {
        rd_kafka_transport_poll_set(t, rd_kafka_schannel_interests(t));
}
static int rd_kafka_schannel_flush(rd_kafka_transport_t *t,
                                   char *errstr,
                                   size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        while (s->output_of < s->output_len) {
                int n =
                    send(t->rktrans_s, (const char *)s->output + s->output_of,
                         (int)(s->output_len - s->output_of), 0);
                if (n == SOCKET_ERROR) {
                        int error = WSAGetLastError();
                        if (error == WSAEWOULDBLOCK || error == WSAEINTR) {
                                rd_kafka_transport_set_blocked(t, rd_true);
                                rd_kafka_schannel_update(t);
                                return 0;
                        }
                        rd_kafka_schannel_error(errstr, errstr_size,
                                                "socket write", error);
                        return -1;
                }
                if (!n) {
                        rd_snprintf(errstr, errstr_size,
                                    "Disconnected: Schannel socket write made "
                                    "no progress");
                        return -1;
                }
                s->output_of += (size_t)n;
        }
        s->output_of = s->output_len = 0;
        rd_kafka_schannel_update(t);
        return 0;
}
static int rd_kafka_schannel_input(rd_kafka_transport_t *t,
                                   char *errstr,
                                   size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        int n;
        if (s->input_len == sizeof(s->input)) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel encrypted input exceeds 64 KiB bound");
                return -1;
        }
        n = recv(t->rktrans_s, (char *)s->input + s->input_len,
                 (int)(sizeof(s->input) - s->input_len), 0);
        if (n == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINTR)
                        return 0;
                rd_kafka_schannel_error(errstr, errstr_size, "socket read",
                                        error);
                return -1;
        }
        if (!n) {
                s->eof = rd_true;
                return 0;
        }
        s->input_len += (size_t)n;
        s->input_incomplete = rd_false;
        s->need_read        = rd_false;
        return 1;
}

static int rd_kafka_schannel_handshake_step(rd_kafka_transport_t *t,
                                            char *errstr,
                                            size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        rd_kafka_schannel_config_t *cfg =
            t->rktrans_rkb->rkb_rk->rk_conf.ssl.tls_ctx;
        SecBuffer input[2], output;
        SecBufferDesc in_desc, out_desc;
        SECURITY_STATUS status;
        TimeStamp expiry;
        size_t extra = 0;
        memset(input, 0, sizeof(input));
        memset(&output, 0, sizeof(output));
        input[0].BufferType = SECBUFFER_TOKEN;
        input[0].pvBuffer   = s->input;
        input[0].cbBuffer   = (ULONG)s->input_len;
        input[1].BufferType = SECBUFFER_EMPTY;
        in_desc.ulVersion   = SECBUFFER_VERSION;
        in_desc.cBuffers    = 2;
        in_desc.pBuffers    = input;
        output.BufferType   = SECBUFFER_TOKEN;
        out_desc.ulVersion  = SECBUFFER_VERSION;
        out_desc.cBuffers   = 1;
        out_desc.pBuffers   = &output;
        status              = InitializeSecurityContextW(
            &cfg->cred, s->have_context ? &s->context : NULL, NULL,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0, SECURITY_NATIVE_DREP, s->have_context ? &in_desc : NULL, 0,
            &s->context, &out_desc, &s->attributes, &expiry);
        /* Target name is supplied by the wide entry point below for the first
         * call; subsequent calls may use NULL, as specified by Schannel. */
        if (SecIsValidHandle(&s->context))
                s->have_context = rd_true;
        if (output.pvBuffer) {
                if (output.cbBuffer > sizeof(s->output)) {
                        FreeContextBuffer(output.pvBuffer);
                        rd_snprintf(
                            errstr, errstr_size,
                            "Schannel handshake output exceeds 64 KiB bound");
                        return -1;
                }
                memcpy(s->output, output.pvBuffer, output.cbBuffer);
                s->output_len = output.cbBuffer;
                s->output_of  = 0;
                FreeContextBuffer(output.pvBuffer);
        }
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
                s->need_read        = rd_true;
                s->input_incomplete = rd_true;
                return 0;
        }
        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
                rd_kafka_schannel_error(errstr, errstr_size,
                                        status == SEC_I_INCOMPLETE_CREDENTIALS
                                            ? "client credential selection"
                                            : "handshake",
                                        (unsigned long)status);
                return -1;
        }
        if (input[1].BufferType == SECBUFFER_EXTRA)
                extra = input[1].cbBuffer;
        if (extra > s->input_len) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel invalid handshake extra buffer");
                return -1;
        }
        if (extra)
                memmove(s->input, s->input + s->input_len - extra, extra);
        s->input_len        = extra;
        s->need_read        = extra ? rd_false : rd_true;
        s->input_incomplete = rd_false;
        if (status == SEC_E_OK)
                s->handshake_done = rd_true;
        rd_kafka_schannel_update(t);
        return 0;
}

static int rd_kafka_schannel_verify(rd_kafka_transport_t *t,
                                    char *errstr,
                                    size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        rd_kafka_schannel_config_t *cfg =
            t->rktrans_rkb->rkb_rk->rk_conf.ssl.tls_ctx;
        PCCERT_CONTEXT peer        = NULL;
        PCCERT_CHAIN_CONTEXT chain = NULL;
        CERT_CHAIN_PARA para;
        CERT_CHAIN_POLICY_PARA policy;
        CERT_CHAIN_POLICY_STATUS policy_status;
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy;
        LPSTR usage = szOID_PKIX_KP_SERVER_AUTH;
        SECURITY_STATUS status;
        DWORD flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
        int ret     = -1;
#ifdef CERT_CHAIN_DISABLE_AIA
        flags |= CERT_CHAIN_DISABLE_AIA;
#endif
        if (!(s->attributes & ISC_RET_CONFIDENTIALITY)) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel did not establish confidentiality");
                return -1;
        }
        status = QueryContextAttributesW(
            &s->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
        if (status != SEC_E_OK) {
                rd_kafka_schannel_error(errstr, errstr_size, "peer certificate",
                                        status);
                goto done;
        }
        memset(&para, 0, sizeof(para));
        para.cbSize                                    = sizeof(para);
        para.RequestedUsage.dwType                     = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier     = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
        if (!CertGetCertificateChain(cfg->engine, peer, NULL, peer->hCertStore,
                                     &para, flags, NULL, &chain))
                goto win_fail;
        memset(&ssl_policy, 0, sizeof(ssl_policy));
        ssl_policy.cbSize         = sizeof(ssl_policy);
        ssl_policy.dwAuthType     = AUTHTYPE_SERVER;
        ssl_policy.pwszServerName = s->hostname;
        memset(&policy, 0, sizeof(policy));
        policy.cbSize            = sizeof(policy);
        policy.pvExtraPolicyPara = &ssl_policy;
        memset(&policy_status, 0, sizeof(policy_status));
        policy_status.cbSize = sizeof(policy_status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
                                              &policy, &policy_status))
                goto win_fail;
        if (policy_status.dwError) {
                rd_kafka_schannel_error(
                    errstr, errstr_size,
                    "server certificate/hostname verification",
                    policy_status.dwError);
                goto done;
        }
        status = QueryContextAttributesW(&s->context, SECPKG_ATTR_STREAM_SIZES,
                                         &s->sizes);
        if (status != SEC_E_OK) {
                rd_kafka_schannel_error(errstr, errstr_size, "stream sizes",
                                        status);
                goto done;
        }
        if (!s->sizes.cbMaximumMessage || (size_t)s->sizes.cbHeader +
                                                  s->sizes.cbMaximumMessage +
                                                  s->sizes.cbTrailer >
                                              sizeof(s->output)) {
                rd_snprintf(
                    errstr, errstr_size,
                    "Schannel stream sizes exceed bounded record buffer");
                goto done;
        }
        s->verified = rd_true;
        ret         = 0;
        goto done;
win_fail:
        rd_kafka_schannel_error(errstr, errstr_size, "certificate chain",
                                GetLastError());
done:
        if (chain)
                CertFreeCertificateChain(chain);
        if (peer)
                CertFreeCertificateContext(peer);
        return ret;
}

static int rd_kafka_schannel_connect(rd_kafka_broker_t *rkb,
                                     rd_kafka_transport_t *t,
                                     char *errstr,
                                     size_t errstr_size) {
        rd_kafka_schannel_session_t *s  = rd_calloc(1, sizeof(*s));
        rd_kafka_schannel_config_t *cfg = rkb->rkb_rk->rk_conf.ssl.tls_ctx;
        char name[RD_KAFKA_NODENAME_SIZE];
        SecBuffer token;
        SecBufferDesc output;
        TimeStamp expiry;
        SECURITY_STATUS status;
        size_t len;
        t->rktrans_tls = s;
        SecInvalidateHandle(&s->context);
        rd_kafka_broker_lock(rkb);
        rd_kafka_nodename_to_hostname(rkb->rkb_nodename, name, sizeof(name));
        rd_kafka_broker_unlock(rkb);
        len = strlen(name);
        if (len > 1 && name[len - 1] == '.')
                name[len - 1] = 0;
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                                 s->hostname, RD_ARRAYSIZE(s->hostname))) {
                rd_snprintf(errstr, errstr_size,
                            "Schannel invalid UTF-8 broker hostname");
                return -1;
        }
        memset(&token, 0, sizeof(token));
        token.BufferType = SECBUFFER_TOKEN;
        output.ulVersion = SECBUFFER_VERSION;
        output.cBuffers  = 1;
        output.pBuffers  = &token;
        status           = InitializeSecurityContextW(
            &cfg->cred, NULL, s->hostname,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0, SECURITY_NATIVE_DREP, NULL, 0, &s->context, &output,
            &s->attributes, &expiry);
        if (SecIsValidHandle(&s->context))
                s->have_context = rd_true;
        if (token.pvBuffer) {
                if (token.cbBuffer <= sizeof(s->output)) {
                        memcpy(s->output, token.pvBuffer, token.cbBuffer);
                        s->output_len = token.cbBuffer;
                }
                FreeContextBuffer(token.pvBuffer);
        }
        if (status != SEC_I_CONTINUE_NEEDED || !s->output_len) {
                rd_kafka_schannel_error(errstr, errstr_size,
                                        "initial handshake", status);
                return -1;
        }
        s->need_read = rd_true;
        return rd_kafka_schannel_flush(t, errstr, errstr_size);
}

static int rd_kafka_schannel_handshake(rd_kafka_transport_t *t) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        char errstr[512];
        int rounds;
        for (rounds = 0; rounds < 32; rounds++) {
                if (rd_kafka_schannel_flush(t, errstr, sizeof(errstr)) == -1)
                        goto fail;
                if (s->output_len)
                        return 0;
                if (s->handshake_done) {
                        if (rd_kafka_schannel_verify(t, errstr,
                                                     sizeof(errstr)) == -1)
                                goto fail;
                        rd_kafka_transport_connect_done(t, NULL);
                        return 1;
                }
                if (s->need_read) {
                        int input =
                            rd_kafka_schannel_input(t, errstr, sizeof(errstr));
                        if (input == -1)
                                goto fail;
                        if (s->eof) {
                                rd_snprintf(errstr, sizeof(errstr),
                                            "Disconnected: EOF during Schannel "
                                            "handshake");
                                goto fail;
                        }
                        if (!input)
                                return 0;
                }
                if (rd_kafka_schannel_handshake_step(t, errstr,
                                                     sizeof(errstr)) == -1)
                        goto fail;
        }
        rd_kafka_schannel_update(t);
        return 0;
fail:
        rd_kafka_broker_fail(t->rktrans_rkb, LOG_ERR, RD_KAFKA_RESP_ERR__SSL,
                             "%s", errstr);
        return -1;
}

static ssize_t rd_kafka_schannel_send(rd_kafka_transport_t *t,
                                      rd_slice_t *slice,
                                      char *errstr,
                                      size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        ssize_t sum                    = 0;
        const void *data;
        size_t size;
        for (;;) {
                if (s->pending_n) {
                        if (slice->buf != s->pending_buf ||
                            rd_slice_abs_offset(slice) != s->pending_offset ||
                            rd_slice_remains(slice) < s->pending_n) {
                                rd_snprintf(errstr, errstr_size,
                                            "Schannel send retry changed the "
                                            "pending request");
                                return -1;
                        }
                        if (rd_kafka_schannel_flush(t, errstr, errstr_size) ==
                            -1)
                                return -1;
                        if (s->output_len)
                                return sum;
                        rd_slice_read(slice, NULL, s->pending_n);
                        sum += (ssize_t)s->pending_n;
                        s->pending_n   = 0;
                        s->pending_buf = NULL;
                }
                size = rd_slice_peeker(slice, &data);
                if (!size)
                        return sum;
                if (!s->verified) {
                        rd_snprintf(errstr, errstr_size,
                                    "Schannel application write before "
                                    "verified handshake");
                        return -1;
                }
                size = RD_MIN(size, RD_MIN((size_t)s->sizes.cbMaximumMessage,
                                           RD_SCHANNEL_PLAIN_CHUNK));
                {
                        SecBuffer buffers[4];
                        SecBufferDesc desc;
                        SECURITY_STATUS status;
                        size_t offset = 0;
                        int i;
                        memset(buffers, 0, sizeof(buffers));
                        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
                        buffers[0].pvBuffer   = s->output;
                        buffers[0].cbBuffer   = s->sizes.cbHeader;
                        buffers[1].BufferType = SECBUFFER_DATA;
                        buffers[1].pvBuffer   = s->output + s->sizes.cbHeader;
                        buffers[1].cbBuffer   = (ULONG)size;
                        memcpy(buffers[1].pvBuffer, data, size);
                        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
                        buffers[2].pvBuffer =
                            s->output + s->sizes.cbHeader + size;
                        buffers[2].cbBuffer   = s->sizes.cbTrailer;
                        buffers[3].BufferType = SECBUFFER_EMPTY;
                        desc.ulVersion        = SECBUFFER_VERSION;
                        desc.cBuffers         = 4;
                        desc.pBuffers         = buffers;
                        status = EncryptMessage(&s->context, 0, &desc, 0);
                        if (status != SEC_E_OK) {
                                rd_kafka_schannel_error(errstr, errstr_size,
                                                        "encryption", status);
                                return -1;
                        }
                        for (i = 0; i < 3; i++) {
                                if (offset + buffers[i].cbBuffer >
                                    sizeof(s->output)) {
                                        rd_snprintf(errstr, errstr_size,
                                                    "Schannel encrypted record "
                                                    "exceeds bound");
                                        return -1;
                                }
                                memmove(s->output + offset, buffers[i].pvBuffer,
                                        buffers[i].cbBuffer);
                                offset += buffers[i].cbBuffer;
                        }
                        s->output_len     = offset;
                        s->output_of      = 0;
                        s->pending_buf    = slice->buf;
                        s->pending_offset = rd_slice_abs_offset(slice);
                        s->pending_n      = size;
                }
        }
}

static ssize_t rd_kafka_schannel_recv(rd_kafka_transport_t *t,
                                      rd_buf_t *rbuf,
                                      char *errstr,
                                      size_t errstr_size) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        ssize_t sum                    = 0;
        void *dest;
        size_t size;
        while ((size = rd_buf_get_writable(rbuf, &dest))) {
                if (s->plaintext_of < s->plaintext_len) {
                        size = RD_MIN(size, s->plaintext_len - s->plaintext_of);
                        memcpy(dest, s->plaintext + s->plaintext_of, size);
                        s->plaintext_of += size;
                        rd_buf_write(rbuf, NULL, size);
                        sum += (ssize_t)size;
                        if (s->plaintext_of == s->plaintext_len)
                                s->plaintext_of = s->plaintext_len = 0;
                        continue;
                }
                if (s->eof) {
                        if (sum)
                                return sum;
                        rd_snprintf(
                            errstr, errstr_size,
                            "Disconnected: Schannel peer closed TLS/socket");
                        return -1;
                }
                if (!s->input_len || s->input_incomplete) {
                        int input;
                        if (sum)
                                return sum;
                        input = rd_kafka_schannel_input(t, errstr, errstr_size);
                        if (input == -1)
                                return -1;
                        if (!input && !s->eof)
                                return 0;
                        if (s->eof)
                                continue;
                }
                {
                        SecBuffer buffers[4];
                        SecBufferDesc desc;
                        SECURITY_STATUS status;
                        size_t extra = 0;
                        int i;
                        memset(buffers, 0, sizeof(buffers));
                        buffers[0].BufferType = SECBUFFER_DATA;
                        buffers[0].pvBuffer   = s->input;
                        buffers[0].cbBuffer   = (ULONG)s->input_len;
                        desc.ulVersion        = SECBUFFER_VERSION;
                        desc.cBuffers         = 4;
                        desc.pBuffers         = buffers;
                        status = DecryptMessage(&s->context, &desc, 0, NULL);
                        if (status == SEC_E_INCOMPLETE_MESSAGE) {
                                s->input_incomplete = rd_true;
                                continue;
                        }
                        if (status == SEC_I_CONTEXT_EXPIRED) {
                                s->eof = rd_true;
                                continue;
                        }
                        if (status == SEC_I_RENEGOTIATE) {
                                rd_snprintf(
                                    errstr, errstr_size,
                                    "Schannel peer requested renegotiation; "
                                    "reconnect required");
                                return -1;
                        }
                        if (status != SEC_E_OK) {
                                rd_kafka_schannel_error(errstr, errstr_size,
                                                        "decryption", status);
                                return -1;
                        }
                        for (i = 0; i < 4; i++) {
                                if (buffers[i].BufferType == SECBUFFER_DATA &&
                                    buffers[i].cbBuffer) {
                                        if (s->plaintext_len +
                                                buffers[i].cbBuffer >
                                            sizeof(s->plaintext)) {
                                                rd_snprintf(
                                                    errstr, errstr_size,
                                                    "Schannel plaintext "
                                                    "exceeds bounded record "
                                                    "buffer");
                                                return -1;
                                        }
                                        memcpy(s->plaintext + s->plaintext_len,
                                               buffers[i].pvBuffer,
                                               buffers[i].cbBuffer);
                                        s->plaintext_len += buffers[i].cbBuffer;
                                } else if (buffers[i].BufferType ==
                                           SECBUFFER_EXTRA)
                                        extra = buffers[i].cbBuffer;
                        }
                        if (extra >= s->input_len) {
                                rd_snprintf(
                                    errstr, errstr_size,
                                    "Schannel decryption made no progress");
                                return -1;
                        }
                        if (extra)
                                memmove(s->input,
                                        s->input + s->input_len - extra, extra);
                        s->input_len        = extra;
                        s->input_incomplete = rd_false;
                }
        }
        return sum;
}

static rd_bool_t rd_kafka_schannel_pending(rd_kafka_transport_t *t) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        return s->plaintext_len > s->plaintext_of ||
               (s->input_len && !s->input_incomplete);
}
static rd_bool_t rd_kafka_schannel_send_pending(rd_kafka_transport_t *t,
                                                const rd_slice_t *slice) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        return s && s->pending_n && s->pending_buf == slice->buf &&
               s->pending_offset == rd_slice_abs_offset(slice);
}
static int rd_kafka_schannel_serve(rd_kafka_transport_t *t,
                                   int events,
                                   char *errstr,
                                   size_t errstr_size) {
        if (events & POLLOUT)
                return rd_kafka_schannel_flush(t, errstr, errstr_size);
        return 0;
}
static void rd_kafka_schannel_close(rd_kafka_transport_t *t) {
        rd_kafka_schannel_session_t *s = t->rktrans_tls;
        if (!s)
                return;
        /* Teardown is abortive: flushing here could transmit a request after
         * timeout/purge already reported its cancellation. */
        if (s->have_context)
                DeleteSecurityContext(&s->context);
        SecureZeroMemory(s, sizeof(*s));
        rd_free(s);
        t->rktrans_tls = NULL;
}
static void rd_kafka_schannel_noop(void) {
}
const rd_kafka_tls_ops_t rd_kafka_schannel_ops = {
    "schannel",
    rd_kafka_schannel_noop,
    rd_kafka_schannel_noop,
    rd_kafka_schannel_ctx_init,
    rd_kafka_schannel_ctx_term,
    rd_kafka_schannel_close,
    rd_kafka_schannel_connect,
    rd_kafka_schannel_handshake,
    rd_kafka_schannel_send,
    rd_kafka_schannel_recv,
    rd_kafka_schannel_pending,
    rd_kafka_schannel_interests,
    rd_kafka_schannel_serve,
    rd_kafka_schannel_send_pending,
    rd_kafka_schannel_noop};
#endif
