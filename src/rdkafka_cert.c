/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
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


/**
 * @name SSL certificates
 *
 */

#include "rdkafka_int.h"
#include "rdkafka_transport_int.h"
#include "rdunittest.h"

#include <ctype.h>


#if WITH_SSL
#include "rdkafka_ssl.h"

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/**
 * @brief OpenSSL password query callback using a conf struct.
 *
 * @locality application thread
 */
static int
rd_kafka_conf_ssl_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
        const rd_kafka_conf_t *conf = userdata;
        int pwlen;

        if (!conf->ssl.key_password)
                return -1;

        pwlen = (int)strlen(conf->ssl.key_password);
        memcpy(buf, conf->ssl.key_password, RD_MIN(pwlen, size));

        return pwlen;
}



static const char *rd_kafka_cert_type_names[] = {"public-key", "private-key",
                                                 "CA"};

static const char *rd_kafka_cert_enc_names[] = {"PKCS#12", "DER", "PEM"};


/**
 * @brief Destroy a certificate
 */
static void rd_kafka_cert_destroy(rd_kafka_cert_t *cert) {
        if (rd_refcnt_sub(&cert->refcnt) > 0)
                return;

        if (cert->x509)
                X509_free(cert->x509);
        if (cert->chain)
                sk_X509_pop_free(cert->chain, X509_free);
        if (cert->pkey)
                EVP_PKEY_free(cert->pkey);
        if (cert->store)
                X509_STORE_free(cert->store);

        rd_free(cert);
}


/**
 * @brief Create a copy of a cert
 */
static rd_kafka_cert_t *rd_kafka_cert_dup(rd_kafka_cert_t *src) {
        rd_refcnt_add(&src->refcnt);
        return src;
}


#if OPENSSL_VERSION_NUMBER < 0x30000000
/**
 * @brief Print the OpenSSL error stack to stdout, for development use.
 */
static RD_UNUSED void rd_kafka_print_ssl_errors(void) {
        unsigned long l;
        const char *file, *data;
        int line, flags;

        while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) !=
               0) {
                char buf[256];

                ERR_error_string_n(l, buf, sizeof(buf));

                printf("ERR: %s:%d: %s: %s:\n", file, line, buf,
                       (flags & ERR_TXT_STRING) ? data : "");
                printf("  %lu:%s : %s : %s : %d : %s (%p, %d, fl 0x%x)\n", l,
                       ERR_lib_error_string(l), ERR_func_error_string(l), file,
                       line,
                       (flags & ERR_TXT_STRING) && data && *data
                           ? data
                           : ERR_reason_error_string(l),
                       data, data ? (int)strlen(data) : -1,
                       flags & ERR_TXT_STRING);
        }
}
#endif


/**
 * @returns a cert structure with a copy of the memory in \p buffer on success,
 *          or NULL on failure in which case errstr will have a human-readable
 *          error string written to it.
 */
static rd_kafka_cert_t *rd_kafka_cert_new(const rd_kafka_conf_t *conf,
                                          rd_kafka_cert_type_t type,
                                          rd_kafka_cert_enc_t encoding,
                                          const void *buffer,
                                          size_t size,
                                          char *errstr,
                                          size_t errstr_size) {
        static const rd_bool_t
            valid[RD_KAFKA_CERT__CNT][RD_KAFKA_CERT_ENC__CNT] = {
                /* Valid encodings per certificate type */
                [RD_KAFKA_CERT_PUBLIC_KEY] = {[RD_KAFKA_CERT_ENC_PKCS12] =
                                                  rd_true,
                                              [RD_KAFKA_CERT_ENC_DER] = rd_true,
                                              [RD_KAFKA_CERT_ENC_PEM] =
                                                  rd_true},
                [RD_KAFKA_CERT_PRIVATE_KEY] =
                    {[RD_KAFKA_CERT_ENC_PKCS12] = rd_true,
                     [RD_KAFKA_CERT_ENC_DER]    = rd_true,
                     [RD_KAFKA_CERT_ENC_PEM]    = rd_true},
                [RD_KAFKA_CERT_CA] = {[RD_KAFKA_CERT_ENC_PKCS12] = rd_true,
                                      [RD_KAFKA_CERT_ENC_DER]    = rd_true,
                                      [RD_KAFKA_CERT_ENC_PEM]    = rd_true},
            };
        const char *action = "", *ssl_errstr = NULL, *extra = "";
        BIO *bio;
        rd_kafka_cert_t *cert = NULL;
        PKCS12 *p12           = NULL;

        if ((int)type < 0 || type >= RD_KAFKA_CERT__CNT) {
                rd_snprintf(errstr, errstr_size, "Invalid certificate type %d",
                            (int)type);
                return NULL;
        }

        if ((int)encoding < 0 || encoding >= RD_KAFKA_CERT_ENC__CNT) {
                rd_snprintf(errstr, errstr_size,
                            "Invalid certificate encoding %d", (int)encoding);
                return NULL;
        }

        if (!valid[type][encoding]) {
                rd_snprintf(errstr, errstr_size,
                            "Invalid encoding %s for certificate type %s",
                            rd_kafka_cert_enc_names[encoding],
                            rd_kafka_cert_type_names[type]);
                return NULL;
        }

        /* Start clean so a failure below reports this call's error only. */
        ERR_clear_error();

        action = "read memory";
        bio    = BIO_new_mem_buf((void *)buffer, (long)size);
        if (!bio)
                goto fail;

        if (encoding == RD_KAFKA_CERT_ENC_PKCS12) {
                action = "read PKCS#12";
                p12    = d2i_PKCS12_bio(bio, NULL);
                if (!p12)
                        goto fail;
        }

        cert           = rd_calloc(1, sizeof(*cert));
        cert->type     = type;
        cert->encoding = encoding;

        rd_refcnt_init(&cert->refcnt, 1);

        switch (type) {
        case RD_KAFKA_CERT_CA:
                cert->store = X509_STORE_new();

                switch (encoding) {
                case RD_KAFKA_CERT_ENC_PKCS12: {
                        EVP_PKEY *ign_pkey;
                        X509 *ign_cert;
                        STACK_OF(X509) *cas = NULL;
                        int i;

                        action = "parse PKCS#12";
                        if (!PKCS12_parse(p12, conf->ssl.key_password,
                                          &ign_pkey, &ign_cert, &cas))
                                goto fail;

                        EVP_PKEY_free(ign_pkey);
                        X509_free(ign_cert);

                        if (!cas || sk_X509_num(cas) < 1) {
                                action =
                                    "retrieve at least one CA "
                                    "cert from PKCS#12";
                                if (cas)
                                        sk_X509_pop_free(cas, X509_free);
                                goto fail;
                        }

                        for (i = 0; i < sk_X509_num(cas); i++) {
                                if (!X509_STORE_add_cert(
                                        cert->store, sk_X509_value(cas, i))) {
                                        action =
                                            "add certificate to "
                                            "X.509 store";
                                        sk_X509_pop_free(cas, X509_free);
                                        goto fail;
                                }
                        }

                        sk_X509_pop_free(cas, X509_free);
                } break;

                case RD_KAFKA_CERT_ENC_DER: {
                        X509 *x509;

                        action = "read DER / X.509 ASN.1";
                        if (!(x509 = d2i_X509_bio(bio, NULL)))
                                goto fail;

                        if (!X509_STORE_add_cert(cert->store, x509)) {
                                action =
                                    "add certificate to "
                                    "X.509 store";
                                X509_free(x509);
                                goto fail;
                        }

                        X509_free(x509);
                } break;

                case RD_KAFKA_CERT_ENC_PEM: {
                        X509 *x509;
                        int cnt = 0;

                        action = "read PEM";

                        /* This will read one certificate per call
                         * until an error occurs or the end of the
                         * buffer is reached (which is an error
                         * we'll need to clear). */
                        while ((x509 = PEM_read_bio_X509(
                                    bio, NULL, rd_kafka_conf_ssl_passwd_cb,
                                    (void *)conf))) {

                                if (!X509_STORE_add_cert(cert->store, x509)) {
                                        action =
                                            "add certificate to "
                                            "X.509 store";
                                        X509_free(x509);
                                        goto fail;
                                }

                                X509_free(x509);
                                cnt++;
                        }

                        if (!BIO_eof(bio)) {
                                /* Encountered parse error before
                                 * reaching end, propagate error and
                                 * fail. */
                                goto fail;
                        }

                        if (!cnt) {
                                action =
                                    "retrieve at least one "
                                    "CA cert from PEM";

                                goto fail;
                        }

                        /* Reached end, which is raised as an error,
                         * so clear it since it is not. */
                        ERR_clear_error();
                } break;

                default:
                        RD_NOTREACHED();
                        break;
                }
                break;


        case RD_KAFKA_CERT_PUBLIC_KEY:
                switch (encoding) {
                case RD_KAFKA_CERT_ENC_PKCS12: {
                        EVP_PKEY *ign_pkey;
                        STACK_OF(X509) *ca = NULL;

                        action = "parse PKCS#12";
                        if (!PKCS12_parse(p12, conf->ssl.key_password,
                                          &ign_pkey, &cert->x509, &ca))
                                goto fail;

                        EVP_PKEY_free(ign_pkey);

                        action = "retrieve public key";
                        if (!cert->x509)
                                goto fail;

                        if (ca) {
                                if (sk_X509_num(ca) > 0)
                                        cert->chain = ca;
                                else
                                        sk_X509_pop_free(ca, X509_free);
                        }
                } break;

                case RD_KAFKA_CERT_ENC_DER:
                        action     = "read DER / X.509 ASN.1";
                        cert->x509 = d2i_X509_bio(bio, NULL);
                        if (!cert->x509)
                                goto fail;
                        break;

                case RD_KAFKA_CERT_ENC_PEM:
                        action     = "read PEM";
                        cert->x509 = PEM_read_bio_X509(
                            bio, NULL, rd_kafka_conf_ssl_passwd_cb,
                            (void *)conf);
                        if (!cert->x509)
                                goto fail;

                        cert->chain = sk_X509_new_null();
                        if (rd_kafka_ssl_read_cert_chain_from_BIO(
                                bio, cert->chain, rd_kafka_conf_ssl_passwd_cb,
                                (void *)conf) != 0) {
                                sk_X509_pop_free(cert->chain, X509_free);
                                cert->chain = NULL;
                                goto fail;
                        }

                        if (sk_X509_num(cert->chain) == 0) {
                                sk_X509_pop_free(cert->chain, X509_free);
                                cert->chain = NULL;
                        }
                        break;

                default:
                        RD_NOTREACHED();
                        break;
                }
                break;


        case RD_KAFKA_CERT_PRIVATE_KEY:
                switch (encoding) {
                case RD_KAFKA_CERT_ENC_PKCS12: {
                        X509 *x509;

                        action = "parse PKCS#12";
                        if (!PKCS12_parse(p12, conf->ssl.key_password,
                                          &cert->pkey, &x509, NULL))
                                goto fail;

                        X509_free(x509);

                        action = "retrieve private key";
                        if (!cert->pkey)
                                goto fail;
                } break;

                case RD_KAFKA_CERT_ENC_DER:
                        action =
                            "read DER / X.509 ASN.1 and "
                            "convert to EVP_PKEY";
                        cert->pkey = d2i_PrivateKey_bio(bio, NULL);
                        if (!cert->pkey)
                                goto fail;
                        break;

                case RD_KAFKA_CERT_ENC_PEM:
                        action     = "read PEM";
                        cert->pkey = PEM_read_bio_PrivateKey(
                            bio, NULL, rd_kafka_conf_ssl_passwd_cb,
                            (void *)conf);
                        if (!cert->pkey)
                                goto fail;
                        break;

                default:
                        RD_NOTREACHED();
                        break;
                }
                break;

        default:
                RD_NOTREACHED();
                break;
        }

        if (bio)
                BIO_free(bio);
        if (p12)
                PKCS12_free(p12);

        return cert;

fail:
        ssl_errstr = rd_kafka_ssl_last_error_str();

        /* OpenSSL 3.x does not provide obsolete ciphers out of the box, so
         * let's try to identify such an error message and guide the user
         * to what to do (set up a provider config file and point to it
         * through the OPENSSL_CONF environment variable).
         * We could call OSSL_PROVIDER_load("legacy") here, but that would be
         * a non-obvious side-effect of calling this set function. */
        if (strstr(action, "parse") && strstr(ssl_errstr, "Algorithm"))
                extra =
                    ": legacy ciphers may require loading OpenSSL's \"legacy\" "
                    "provider through an OPENSSL_CONF configuration file";

        rd_snprintf(errstr, errstr_size, "Failed to %s %s (encoding %s): %s%s",
                    action, rd_kafka_cert_type_names[type],
                    rd_kafka_cert_enc_names[encoding], ssl_errstr, extra);

        if (cert)
                rd_kafka_cert_destroy(cert);
        if (bio)
                BIO_free(bio);
        if (p12)
                PKCS12_free(p12);

        /* The reason has been copied to errstr, don't leave it on the queue
         * where a later unrelated failure would report it again. */
        ERR_clear_error();

        return NULL;
}
#endif /* WITH_SSL */


#if WITH_SCHANNEL
#include "rdkafka_schannel.h"
#define RD_KAFKA_SCHANNEL_CERT_LIMIT (16 * 1024 * 1024)

static int rd_kafka_schannel_space(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Windows message text for a status code, without the trailing period and
 * line break. */
const char *
rd_kafka_schannel_status_text(unsigned long status, char *buf, size_t size) {
        size_t len;
        buf[0] = '\0';
        if (!FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, (DWORD)status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, (DWORD)size, NULL))
                buf[0] = '\0';
        len = strlen(buf);
        while (len > 0 && strchr(" .\r\n", buf[len - 1]))
                buf[--len] = '\0';
        if (!len)
                rd_snprintf(buf, size, "no Windows message text");
        return buf;
}

int rd_kafka_schannel_add_certs(HCERTSTORE store, const void *data, size_t size,
                               rd_kafka_cert_enc_t encoding,
                               PCCERT_CONTEXT *first, char *errstr,
                               size_t errstr_size) {
        const char *begin = "-----BEGIN CERTIFICATE-----";
        const char *end = "-----END CERTIFICATE-----";
        char *text = NULL, *p;
        int count = 0, ok = 0;
        PCCERT_CONTEXT cert = NULL, stored = NULL;
        if (first) *first = NULL;
        if (!data || !size || size > RD_KAFKA_SCHANNEL_CERT_LIMIT)
                goto fail;
        if (encoding == RD_KAFKA_CERT_ENC_DER) {
                cert = CertCreateCertificateContext(X509_ASN_ENCODING, data,
                                                     (DWORD)size);
                if (!cert || cert->cbCertEncoded != size ||
                    !CertAddCertificateContextToStore(store, cert,
                        CERT_STORE_ADD_ALWAYS, &stored)) goto fail;
                if (first) *first = CertDuplicateCertificateContext(stored);
                ok = 1;
                goto done;
        }
        if (encoding != RD_KAFKA_CERT_ENC_PEM) goto fail;
        text = rd_malloc(size + 1);
        memcpy(text, data, size); text[size] = 0;
        if (strlen(text) != size) goto fail;
        p = text;
        while (*p) {
                char *finish;
                BYTE *der;
                DWORD der_size = 0;
                size_t block;
                while (rd_kafka_schannel_space(*p)) p++;
                if (!*p) break;
                if (strncmp(p, begin, strlen(begin))) goto fail;
                finish = strstr(p + strlen(begin), end);
                if (!finish) goto fail;
                finish += strlen(end);
                block = (size_t)(finish - p);
                if (!CryptStringToBinaryA(p, (DWORD)block,
                    CRYPT_STRING_BASE64HEADER, NULL, &der_size, NULL, NULL)) goto fail;
                der = rd_malloc(der_size);
                if (!CryptStringToBinaryA(p, (DWORD)block,
                    CRYPT_STRING_BASE64HEADER, der, &der_size, NULL, NULL)) {
                        rd_free(der); goto fail;
                }
                cert = CertCreateCertificateContext(X509_ASN_ENCODING, der, der_size);
                rd_free(der);
                if (!cert || !CertAddCertificateContextToStore(store, cert,
                    CERT_STORE_ADD_ALWAYS, &stored)) goto fail;
                if (!count && first) *first = CertDuplicateCertificateContext(stored);
                CertFreeCertificateContext(stored); stored = NULL;
                CertFreeCertificateContext(cert); cert = NULL;
                count++; p = finish;
        }
        if (!count) goto fail;
        ok = 1;
        goto done;
fail: {
        char text[256];
        unsigned long status = (unsigned long)GetLastError();
        rd_snprintf(errstr, errstr_size,
                    "Schannel rejected certificate encoding (PEM "
                    "chain or DER required, max 16 MiB): %s "
                    "(0x%08lx)",
                    rd_kafka_schannel_status_text(status, text, sizeof(text)),
                    status);
}
        if (first && *first) {
                CertFreeCertificateContext(*first); *first = NULL;
        }
done:
        if (stored) CertFreeCertificateContext(stored);
        if (cert) CertFreeCertificateContext(cert);
        rd_free(text);
        return ok ? 0 : -1;
}

int rd_kafka_schannel_import_key(const void *data, size_t size,
                                rd_kafka_cert_enc_t encoding,
                                NCRYPT_PROV_HANDLE *provider,
                                NCRYPT_KEY_HANDLE *key, char *errstr,
                                size_t errstr_size) {
        BYTE *der = NULL;
        const BYTE *input = data;
        DWORD input_size = (DWORD)size;
        SECURITY_STATUS status = NTE_BAD_DATA;
        *provider = 0; *key = 0;
        if (!data || !size || size > RD_KAFKA_SCHANNEL_CERT_LIMIT) goto fail;
        if (encoding == RD_KAFKA_CERT_ENC_PEM) {
                char *text = rd_malloc(size + 1);
                char *p;
                memcpy(text, data, size); text[size] = 0; p = text;
                while (rd_kafka_schannel_space(*p)) p++;
                if (strlen(text) != size ||
                    strncmp(p, "-----BEGIN PRIVATE KEY-----", 27) ||
                    !CryptStringToBinaryA(p, (DWORD)strlen(p), CRYPT_STRING_BASE64HEADER,
                                         NULL, &input_size, NULL, NULL)) {
                        SecureZeroMemory(text, size); rd_free(text); goto fail;
                }
                der = rd_malloc(input_size);
                if (!CryptStringToBinaryA(p, (DWORD)strlen(p), CRYPT_STRING_BASE64HEADER,
                                          der, &input_size, NULL, NULL)) {
                        SecureZeroMemory(text, size); rd_free(text); goto fail;
                }
                SecureZeroMemory(text, size); rd_free(text); input = der;
        } else if (encoding != RD_KAFKA_CERT_ENC_DER) goto fail;
        status = NCryptOpenStorageProvider(provider, MS_KEY_STORAGE_PROVIDER, 0);
        if (status != ERROR_SUCCESS) goto fail;
        status = NCryptImportKey(*provider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                                NULL, key, (PBYTE)input, input_size, NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) goto fail;
        if (der) { SecureZeroMemory(der, input_size); rd_free(der); }
        return 0;
fail:
        if (der) { SecureZeroMemory(der, input_size); rd_free(der); }
        if (*key) NCryptFreeObject(*key);
        if (*provider) NCryptFreeObject(*provider);
        *key = 0; *provider = 0;
        {
                char text[256];
                rd_snprintf(errstr, errstr_size,
                            "Schannel requires an unencrypted PKCS#8 private "
                            "key (PEM/DER); CNG import failed: %s (0x%08lx)",
                            rd_kafka_schannel_status_text((unsigned long)status,
                                                          text, sizeof(text)),
                            (unsigned long)status);
        }
        return -1;
}

static void rd_kafka_cert_destroy(rd_kafka_cert_t *cert) {
        if (rd_refcnt_sub(&cert->refcnt) > 0) return;
        if (cert->win_cert) CertFreeCertificateContext(cert->win_cert);
        if (cert->win_store) CertCloseStore(cert->win_store, 0);
        if (cert->win_key) NCryptFreeObject((NCRYPT_HANDLE)cert->win_key);
        if (cert->win_provider) NCryptFreeObject((NCRYPT_HANDLE)cert->win_provider);
        rd_free(cert);
}
static rd_kafka_cert_t *rd_kafka_cert_dup(rd_kafka_cert_t *cert) {
        rd_refcnt_add(&cert->refcnt); return cert;
}
static rd_kafka_cert_t *rd_kafka_cert_new(const rd_kafka_conf_t *conf,
                                        rd_kafka_cert_type_t type,
                                        rd_kafka_cert_enc_t encoding,
                                        const void *buffer, size_t size,
                                        char *errstr, size_t errstr_size) {
        rd_kafka_cert_t *cert = rd_calloc(1, sizeof(*cert));
        (void)conf;
        cert->type = type; cert->encoding = encoding;
        rd_refcnt_init(&cert->refcnt, 1);
        if (type == RD_KAFKA_CERT_PRIVATE_KEY) {
                NCRYPT_PROV_HANDLE provider;
                NCRYPT_KEY_HANDLE key;
                if (rd_kafka_schannel_import_key(buffer, size, encoding,
                    &provider, &key, errstr, errstr_size) == -1) goto fail;
                cert->win_provider = (uintptr_t)provider;
                cert->win_key = (uintptr_t)key;
        } else {
                PCCERT_CONTEXT first = NULL;
                cert->win_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
                if (!cert->win_store || rd_kafka_schannel_add_certs(cert->win_store,
                    buffer, size, encoding, &first, errstr, errstr_size) == -1) goto fail;
                cert->win_cert = (void *)first;
        }
        return cert;
fail:
        rd_kafka_cert_destroy(cert); return NULL;
}
#endif

/**
 * @name Public API
 * @brief These public methods must be available regardless if
 *        librdkafka was built with OpenSSL or not.
 * @{
 */

/**
 * @brief Parse an `ssl.certificate.store` selector:
 *        [Cert:][/]{CurrentUser|LocalMachine}/My/THUMBPRINT.
 *
 * Accepts `\` or `/`, any case, and ignores spaces and the invisible
 * marks (U+200E, U+200F, U+FEFF) that copying from the certificate
 * manager inserts.
 *
 * @returns 0 with \p location and \p thumbprint set, else -1 and \p errstr.
 */
int rd_kafka_cert_store_selector_parse(const char *selector,
                                       rd_kafka_cert_store_location_t *location,
                                       unsigned char thumbprint[20],
                                       char *errstr,
                                       size_t errstr_size) {
        char norm[256];
        const unsigned char *s = (const unsigned char *)selector;
        size_t n               = 0;
        char *path, *store, *hex;
        size_t i;

        while (*s) {
                if ((s[0] == 0xe2 && s[1] == 0x80 &&
                     (s[2] == 0x8e || s[2] == 0x8f)) ||
                    (s[0] == 0xef && s[1] == 0xbb && s[2] == 0xbf)) {
                        s += 3;
                        continue;
                }
                if (*s == ' ' || *s == '\t') {
                        s++;
                        continue;
                }
                if (n + 1 >= sizeof(norm))
                        goto bad_format;
                norm[n++] = *s == '\\' ? '/' : (char)tolower(*s);
                s++;
        }
        norm[n] = '\0';

        path = norm;
        if (!strncmp(path, "cert:", 5))
                path += 5;
        if (*path == '/')
                path++;
        if (!strncmp(path, "currentuser/", 12)) {
                *location = RD_KAFKA_CERT_STORE_CURRENT_USER;
                store     = path + 12;
        } else if (!strncmp(path, "localmachine/", 13)) {
                *location = RD_KAFKA_CERT_STORE_LOCAL_MACHINE;
                store     = path + 13;
        } else
                goto bad_format;
        if (!(hex = strchr(store, '/')))
                goto bad_format;
        *hex++ = '\0';
        if (strcmp(store, "my")) {
                rd_snprintf(errstr, errstr_size,
                            "ssl.certificate.store supports only the My "
                            "(personal) store, not \"%s\"",
                            store);
                return -1;
        }
        if (strlen(hex) != 40 || strspn(hex, "0123456789abcdef") != 40) {
                rd_snprintf(errstr, errstr_size,
                            "ssl.certificate.store thumbprint must be 40 "
                            "hexadecimal digits, not \"%s\"",
                            hex);
                return -1;
        }
        for (i = 0; i < 20; i++) {
                char byte[3]  = {hex[i * 2], hex[i * 2 + 1], '\0'};
                thumbprint[i] = (unsigned char)strtoul(byte, NULL, 16);
        }
        return 0;

bad_format:
        rd_snprintf(errstr, errstr_size,
                    "ssl.certificate.store must be "
                    "CurrentUser/My/<thumbprint> or "
                    "LocalMachine/My/<thumbprint>");
        return -1;
}

/**
 * @brief Selector parser variants, in particular as copied from PowerShell
 *        and the certificate manager.
 */
int unittest_cert_store_selector(void) {
        const struct {
                const char *selector;
                int ok;
                rd_kafka_cert_store_location_t location;
        } cases[] = {
            {"CurrentUser/My/0123456789abcdef0123456789ABCDEF01234567", 1,
             RD_KAFKA_CERT_STORE_CURRENT_USER},
            {"localmachine\\my\\0123456789ABCDEF0123456789abcdef01234567", 1,
             RD_KAFKA_CERT_STORE_LOCAL_MACHINE},
            {"Cert:"
             "\\LocalMachine\\My\\0123456789abcdef0123456789abcdef01234567",
             1, RD_KAFKA_CERT_STORE_LOCAL_MACHINE},
            {"Cert:/CurrentUser/MY/0123456789abcdef0123456789abcdef01234567", 1,
             RD_KAFKA_CERT_STORE_CURRENT_USER},
            /* MMC: leading U+200E and space-separated byte pairs. */
            {"CurrentUser/My/\xe2\x80\x8e"
             "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67",
             1, RD_KAFKA_CERT_STORE_CURRENT_USER},
            {" CurrentUser / My / 0123456789abcdef0123456789abcdef01234567 ", 1,
             RD_KAFKA_CERT_STORE_CURRENT_USER},
            {"CurrentUser/Root/0123456789abcdef0123456789abcdef01234567", 0},
            {"Users/My/0123456789abcdef0123456789abcdef01234567", 0},
            {"CurrentUser/My/0123456789abcdef0123456789abcdef0123456", 0},
            {"CurrentUser/My/0123456789abcdef0123456789abcdef0123456g", 0},
            {"CurrentUser/My", 0},
            {"", 0},
        };
        size_t i;

        for (i = 0; i < RD_ARRAYSIZE(cases); i++) {
                rd_kafka_cert_store_location_t location;
                unsigned char hash[20];
                char errstr[256] = "";
                int r            = rd_kafka_cert_store_selector_parse(
                    cases[i].selector, &location, hash, errstr, sizeof(errstr));
                RD_UT_ASSERT((r == 0) == cases[i].ok,
                             "case %" PRIusz " \"%s\": expected %s, got %s", i,
                             cases[i].selector,
                             cases[i].ok ? "success" : "failure",
                             r == 0 ? "success" : errstr);
                if (!cases[i].ok) {
                        RD_UT_ASSERT(strstr(errstr, "ssl.certificate.store"),
                                     "case %" PRIusz
                                     ": error must name the "
                                     "property: %s",
                                     i, errstr);
                        continue;
                }
                RD_UT_ASSERT(location == cases[i].location,
                             "case %" PRIusz ": wrong store location", i);
                RD_UT_ASSERT(hash[0] == 0x01 && hash[7] == 0xef &&
                                 hash[19] == 0x67,
                             "case %" PRIusz ": wrong thumbprint bytes", i);
        }
        RD_UT_PASS();
}


rd_kafka_conf_res_t rd_kafka_conf_set_ssl_cert(rd_kafka_conf_t *conf,
                                               rd_kafka_cert_type_t cert_type,
                                               rd_kafka_cert_enc_t cert_enc,
                                               const void *buffer,
                                               size_t size,
                                               char *errstr,
                                               size_t errstr_size) {
#if !WITH_TLS
        rd_snprintf(errstr, errstr_size,
                    "librdkafka not built with TLS support");
        return RD_KAFKA_CONF_INVALID;
#else
        rd_kafka_cert_t *cert;
        rd_kafka_cert_t **cert_map[RD_KAFKA_CERT__CNT] = {
            [RD_KAFKA_CERT_PUBLIC_KEY]  = &conf->ssl.cert,
            [RD_KAFKA_CERT_PRIVATE_KEY] = &conf->ssl.key,
            [RD_KAFKA_CERT_CA]          = &conf->ssl.ca};
        rd_kafka_cert_t **certp;

        if ((int)cert_type < 0 || cert_type >= RD_KAFKA_CERT__CNT) {
                rd_snprintf(errstr, errstr_size, "Invalid certificate type %d",
                            (int)cert_type);
                return RD_KAFKA_CONF_INVALID;
        }

        /* Make sure OpenSSL is loaded */
        rd_kafka_global_init();

        certp = cert_map[cert_type];

        if (!buffer) {
                /* Clear current value */
                if (*certp) {
                        rd_kafka_cert_destroy(*certp);
                        *certp = NULL;
                }
                return RD_KAFKA_CONF_OK;
        }

        cert = rd_kafka_cert_new(conf, cert_type, cert_enc, buffer, size,
                                 errstr, errstr_size);
        if (!cert)
                return RD_KAFKA_CONF_INVALID;

        if (*certp)
                rd_kafka_cert_destroy(*certp);

        *certp = cert;

        return RD_KAFKA_CONF_OK;
#endif
}



/**
 * @brief Destructor called when configuration object is destroyed.
 */
void rd_kafka_conf_cert_dtor(int scope, void *pconf) {
#if WITH_TLS
        rd_kafka_conf_t *conf = pconf;
        assert(scope == _RK_GLOBAL);
        if (conf->ssl.key) {
                rd_kafka_cert_destroy(conf->ssl.key);
                conf->ssl.key = NULL;
        }
        if (conf->ssl.cert) {
                rd_kafka_cert_destroy(conf->ssl.cert);
                conf->ssl.cert = NULL;
        }
        if (conf->ssl.ca) {
                rd_kafka_cert_destroy(conf->ssl.ca);
                conf->ssl.ca = NULL;
        }
#endif
}

/**
 * @brief Copy-constructor called when configuration object \p psrcp is
 *        duplicated to \p dstp.
 */
void rd_kafka_conf_cert_copy(int scope,
                             void *pdst,
                             const void *psrc,
                             void *dstptr,
                             const void *srcptr,
                             size_t filter_cnt,
                             const char **filter) {
#if WITH_TLS
        rd_kafka_conf_t *dconf       = pdst;
        const rd_kafka_conf_t *sconf = psrc;

        assert(scope == _RK_GLOBAL);

        /* Free and reset any exist certs on the destination conf */
        rd_kafka_conf_cert_dtor(scope, pdst);

        if (sconf->ssl.key)
                dconf->ssl.key = rd_kafka_cert_dup(sconf->ssl.key);

        if (sconf->ssl.cert)
                dconf->ssl.cert = rd_kafka_cert_dup(sconf->ssl.cert);

        if (sconf->ssl.ca)
                dconf->ssl.ca = rd_kafka_cert_dup(sconf->ssl.ca);
#endif
}


/**@}*/
