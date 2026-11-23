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
/* OpenSSL implementation of the private crypto service interface. */
#include "rd.h"
#include "tinycthread.h"
#include "rdkafka_crypto.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#include <openssl/ecdsa.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new  EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !WITH_SSL
static mtx_t *crypto_locks;
static int crypto_lock_count;
static void lock_cb(int mode, int i, const char *file, int line) {
        (void)file;
        (void)line;
        if (mode & CRYPTO_LOCK)
                mtx_lock(&crypto_locks[i]);
        else
                mtx_unlock(&crypto_locks[i]);
}
static unsigned long thread_cb(void) {
        return thrd_current_id();
}
#endif
static void global_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !WITH_SSL
        int i;
        if (!CRYPTO_get_locking_callback()) {
                crypto_lock_count = CRYPTO_num_locks();
                crypto_locks      = rd_malloc((size_t)crypto_lock_count *
                                              sizeof(*crypto_locks));
                for (i = 0; i < crypto_lock_count; i++)
                        mtx_init(&crypto_locks[i], mtx_plain);
                CRYPTO_set_locking_callback(lock_cb);
                CRYPTO_set_id_callback(thread_cb);
        }
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
#endif
}
static void global_term(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !WITH_SSL
        int i;
        if (CRYPTO_get_locking_callback() == lock_cb) {
                CRYPTO_set_locking_callback(NULL);
                CRYPTO_set_id_callback(NULL);
                for (i = 0; i < crypto_lock_count; i++)
                        mtx_destroy(&crypto_locks[i]);
                rd_free(crypto_locks);
                crypto_locks = NULL;
        }
#endif
}
static void thread_term(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
        /* Modern OpenSSL releases thread state automatically. */
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
        ERR_remove_thread_state(NULL);
#endif
}
struct rd_kafka_crypto_key_s {
        EVP_PKEY *key;
};
static const EVP_MD *md(rd_kafka_crypto_hash_t h) {
        switch (h) {
        case RD_KAFKA_CRYPTO_SHA1:
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
                return EVP_sha1();
#else
                return NULL;
#endif
        case RD_KAFKA_CRYPTO_SHA256:
#ifndef OPENSSL_NO_SHA256
                return EVP_sha256();
#else
                return NULL;
#endif
        case RD_KAFKA_CRYPTO_SHA512:
#ifndef OPENSSL_NO_SHA512
                return EVP_sha512();
#else
                return NULL;
#endif
        default:
                return NULL;
        }
}
static int
digest(rd_kafka_crypto_hash_t h, const void *p, size_t n, unsigned char *out) {
        unsigned int size;
        return md(h) && EVP_Digest(p, n, out, &size, md(h), NULL) == 1 ? 0 : -1;
}
static int hmac(rd_kafka_crypto_hash_t h,
                const void *key,
                size_t kn,
                const void *p,
                size_t n,
                unsigned char *out) {
        unsigned int size;
        return kn <= INT_MAX && md(h) &&
                       HMAC(md(h), kn ? key : "", (int)kn, n ? p : "", n, out,
                            &size)
                   ? 0
                   : -1;
}
static int pbkdf2(rd_kafka_crypto_hash_t h,
                  const void *key,
                  size_t kn,
                  const void *salt,
                  size_t sn,
                  uint64_t it,
                  unsigned char *out,
                  size_t n) {
        if (kn > INT_MAX || sn > INT_MAX || it > INT_MAX || n > INT_MAX ||
            !md(h))
                return -1;
        return PKCS5_PBKDF2_HMAC(key, (int)kn, salt, (int)sn, (int)it, md(h),
                                 (int)n, out) == 1
                   ? 0
                   : -1;
}
static int random_bytes(void *p, size_t n) {
        unsigned char *out = p;
        while (n) {
                int chunk = n > INT_MAX ? INT_MAX : (int)n;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                if (RAND_priv_bytes(out, chunk) != 1)
                        return -1;
#else
                if (RAND_bytes(out, chunk) != 1)
                        return -1;
#endif
                out += chunk;
                n -= (size_t)chunk;
        }
        return 0;
}
static int password_cb(char *out, int n, int rw, void *opaque) {
        const char *password = opaque;
        size_t size          = password ? strlen(password) : 0;
        (void)rw;
        if (size > (size_t)n)
                return 0;
        if (size)
                memcpy(out, password, size);
        return (int)size;
}
static rd_kafka_crypto_key_t *
key_load(const void *pem, size_t n, const char *password, char *e, size_t en) {
        BIO *bio;
        rd_kafka_crypto_key_t *k;
        if (n > INT_MAX) {
                snprintf(e, en, "OpenSSL private key is too large");
                return NULL;
        }
        bio = BIO_new_mem_buf((void *)pem, (int)n);
        k   = calloc(1, sizeof(*k));
        if (bio && k)
                k->key = PEM_read_bio_PrivateKey(bio, NULL, password_cb,
                                                 (void *)password);
        BIO_free(bio);
        if (!k || !k->key) {
                free(k);
                snprintf(e, en, "OpenSSL private key import failed");
                return NULL;
        }
        return k;
}
static void key_destroy(rd_kafka_crypto_key_t *k) {
        EVP_PKEY_free(k->key);
        free(k);
}
static int sign_data(rd_kafka_crypto_key_t *k,
                     rd_kafka_crypto_signature_t alg,
                     const void *p,
                     size_t n,
                     unsigned char **out,
                     size_t *on,
                     char *e,
                     size_t en) {
        EVP_MD_CTX *ctx     = NULL;
        EVP_PKEY_CTX *pkctx = NULL;
        unsigned char *sig  = NULL;
        size_t size         = 0;
        int ok              = 0;
        if (alg == RD_KAFKA_CRYPTO_RS256) {
#ifndef OPENSSL_NO_RSA
                if (EVP_PKEY_base_id(k->key) != EVP_PKEY_RSA)
                        goto done;
#else
                snprintf(e, en,
                         "OpenSSL RS256 signing is unavailable: RSA disabled");
                return -1;
#endif
        } else if (alg == RD_KAFKA_CRYPTO_ES256) {
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
                char name[80];
                size_t name_len = 0;
                if (EVP_PKEY_is_a(k->key, "EC") != 1 ||
                    EVP_PKEY_get_group_name(k->key, name, sizeof(name),
                                            &name_len) != 1 ||
                    (strcmp(name, "prime256v1") && strcmp(name, "P-256") &&
                     strcmp(name, "secp256r1")))
                        goto done;
#else
                EC_KEY *ec;
                const EC_GROUP *group;
                int curve;
                if (EVP_PKEY_base_id(k->key) != EVP_PKEY_EC)
                        goto done;
                ec = EVP_PKEY_get1_EC_KEY(k->key);
                if (!ec)
                        goto done;
                group = EC_KEY_get0_group(ec);
                curve = EC_GROUP_get_curve_name(group);
                EC_KEY_free(ec);
                if (curve != NID_X9_62_prime256v1)
                        goto done;
#endif
#else
                snprintf(
                    e, en,
                    "OpenSSL ES256 signing is unavailable: EC/ECDSA disabled");
                return -1;
#endif
        } else
                goto done;
        ctx = EVP_MD_CTX_new();
        if (!md(RD_KAFKA_CRYPTO_SHA256) || !ctx ||
            EVP_DigestSignInit(ctx, &pkctx, md(RD_KAFKA_CRYPTO_SHA256), NULL,
                               k->key) != 1)
                goto done;
#ifndef OPENSSL_NO_RSA
        if (alg == RD_KAFKA_CRYPTO_RS256 &&
            EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
                goto done;
#endif
        if (EVP_DigestSignUpdate(ctx, p, n) != 1 ||
            EVP_DigestSignFinal(ctx, NULL, &size) != 1)
                goto done;
        sig = malloc(size);
        if (!sig || EVP_DigestSignFinal(ctx, sig, &size) != 1)
                goto done;
        if (alg == RD_KAFKA_CRYPTO_ES256) {
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
                const unsigned char *q = sig;
                const BIGNUM *r, *s;
                ECDSA_SIG *v = d2i_ECDSA_SIG(NULL, &q, (long)size);
                unsigned char raw[64];
                int rn, sn;
                if (!v || q != sig + size) {
                        ECDSA_SIG_free(v);
                        goto done;
                }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                ECDSA_SIG_get0(v, &r, &s);
#else
                r = v->r;
                s = v->s;
#endif
                rn = BN_num_bytes(r);
                sn = BN_num_bytes(s);
                if (rn > 32 || sn > 32) {
                        ECDSA_SIG_free(v);
                        goto done;
                }
                memset(raw, 0, sizeof(raw));
                BN_bn2bin(r, raw + 32 - rn);
                BN_bn2bin(s, raw + 64 - sn);
                ECDSA_SIG_free(v);
                free(sig);
                sig = malloc(64);
                if (!sig)
                        goto done;
                memcpy(sig, raw, 64);
                size = 64;
#else
                goto done;
#endif
        }
        *out = sig;
        *on  = size;
        sig  = NULL;
        ok   = 1;
done:
        free(sig);
        EVP_MD_CTX_free(ctx);
        if (!ok)
                snprintf(e, en,
                         "OpenSSL signing failed or algorithm/key mismatch");
        return ok ? 0 : -1;
}
const rd_kafka_crypto_ops_t rd_kafka_crypto_openssl_ops = {
    "openssl", global_init,  global_term, thread_term, digest,     hmac,
    pbkdf2,    random_bytes, key_load,    sign_data,   key_destroy};
