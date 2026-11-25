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
#include "rdkafka_crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#include <openssl/ecdsa.h>
#endif
#include <limits.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new  EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

/* This adapter is built only with OpenSSL broker TLS, and rdkafka_ssl.c
 * owns the OpenSSL global and per-thread state. */
static void global_noop(void) {
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

static rd_kafka_crypto_key_t *
key_load(const void *pem, size_t n, const char *password, char *e, size_t en) {
        BIO *bio;
        rd_kafka_crypto_key_t *k;
        if (n > INT_MAX) {
                rd_snprintf(e, en, "OpenSSL private key is too large");
                return NULL;
        }
        bio = BIO_new_mem_buf((void *)pem, (int)n);
        k   = rd_calloc(1, sizeof(*k));
        if (bio)
                k->key =
                    PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)password);
        BIO_free(bio);
        if (!k->key) {
                rd_free(k);
                rd_snprintf(e, en, "OpenSSL private key import failed");
                return NULL;
        }
        return k;
}

static void key_destroy(rd_kafka_crypto_key_t *k) {
        EVP_PKEY_free(k->key);
        rd_free(k);
}

#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
static rd_bool_t is_p256_key(EVP_PKEY *key) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
        char name[80];
        size_t name_len = 0;
        return EVP_PKEY_is_a(key, "EC") == 1 &&
               EVP_PKEY_get_group_name(key, name, sizeof(name), &name_len) ==
                   1 &&
               (!strcmp(name, "prime256v1") || !strcmp(name, "P-256") ||
                !strcmp(name, "secp256r1"));
#else
        EC_KEY *ec;
        int curve;
        if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
                return rd_false;
        ec = EVP_PKEY_get1_EC_KEY(key);
        if (!ec)
                return rd_false;
        curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
        EC_KEY_free(ec);
        return curve == NID_X9_62_prime256v1;
#endif
}

/**
 * @brief Convert the DER ECDSA-Sig-Value in \p der to the 64-byte R || S
 *        form of RFC 7518 section 3.4, in \p raw.
 */
static rd_bool_t
es256_der_to_raw(const unsigned char *der, size_t size, unsigned char *raw) {
        const unsigned char *q = der;
        const BIGNUM *r, *s;
        ECDSA_SIG *v = d2i_ECDSA_SIG(NULL, &q, (long)size);
        rd_bool_t ok = rd_false;
        if (!v || q != der + size)
                goto done;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        ECDSA_SIG_get0(v, &r, &s);
#else
        r = v->r;
        s = v->s;
#endif
        if (BN_num_bytes(r) > 32 || BN_num_bytes(s) > 32)
                goto done;
        memset(raw, 0, 64);
        BN_bn2bin(r, raw + 32 - BN_num_bytes(r));
        BN_bn2bin(s, raw + 64 - BN_num_bytes(s));
        ok = rd_true;
done:
        ECDSA_SIG_free(v);
        return ok;
}
#endif

static int sign_data(rd_kafka_crypto_key_t *k,
                     rd_kafka_crypto_signature_t alg,
                     const void *p,
                     size_t n,
                     unsigned char **out,
                     size_t *on,
                     char *e,
                     size_t en) {
        EVP_MD_CTX *ctx    = NULL;
        unsigned char *sig = NULL;
        size_t size        = 0;
        int ok             = 0;
        if (alg == RD_KAFKA_CRYPTO_ES256) {
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
                if (!is_p256_key(k->key)) {
                        rd_snprintf(e, en, "ES256 requires a P-256 EC key");
                        return -1;
                }
#else
                rd_snprintf(e, en, "ES256 is not available: EC disabled");
                return -1;
#endif
        } else if (alg != RD_KAFKA_CRYPTO_RS256)
                goto done;
        ctx = EVP_MD_CTX_new();
        if (!md(RD_KAFKA_CRYPTO_SHA256) || !ctx ||
            EVP_DigestSignInit(ctx, NULL, md(RD_KAFKA_CRYPTO_SHA256), NULL,
                               k->key) != 1 ||
            EVP_DigestSignUpdate(ctx, p, n) != 1 ||
            EVP_DigestSignFinal(ctx, NULL, &size) != 1)
                goto done;
        sig = rd_malloc(size);
        if (EVP_DigestSignFinal(ctx, sig, &size) != 1)
                goto done;
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
        if (alg == RD_KAFKA_CRYPTO_ES256) {
                unsigned char *raw = rd_malloc(64);
                if (!es256_der_to_raw(sig, size, raw)) {
                        rd_free(raw);
                        goto done;
                }
                rd_free(sig);
                sig  = raw;
                size = 64;
        }
#endif
        *out = sig;
        *on  = size;
        sig  = NULL;
        ok   = 1;
done:
        RD_IF_FREE(sig, rd_free);
        EVP_MD_CTX_free(ctx);
        if (!ok)
                rd_snprintf(e, en, "OpenSSL signing failed");
        return ok ? 0 : -1;
}

const rd_kafka_crypto_ops_t rd_kafka_crypto_openssl_ops = {
    "openssl", global_noop,  global_noop, global_noop, digest,     hmac,
    pbkdf2,    random_bytes, key_load,    sign_data,   key_destroy};
