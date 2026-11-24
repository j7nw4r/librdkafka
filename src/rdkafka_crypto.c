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
#include "rd.h"
#include "rdkafka_crypto.h"
#if WITH_CRYPTO_OPENSSL
const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops =
    &rd_kafka_crypto_openssl_ops;
#else
const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops = NULL;
#endif
void rd_kafka_crypto_init(void) {
        if (rd_kafka_crypto_ops)
                rd_kafka_crypto_ops->global_init();
}
void rd_kafka_crypto_term(void) {
        if (rd_kafka_crypto_ops)
                rd_kafka_crypto_ops->global_term();
}
void rd_kafka_crypto_thread_term(void) {
        if (rd_kafka_crypto_ops)
                rd_kafka_crypto_ops->thread_term();
}
size_t rd_kafka_crypto_digest_size(rd_kafka_crypto_hash_t h) {
        switch (h) {
        case RD_KAFKA_CRYPTO_SHA1:
                return 20;
        case RD_KAFKA_CRYPTO_SHA256:
                return 32;
        case RD_KAFKA_CRYPTO_SHA512:
                return 64;
        default:
                return 0;
        }
}
void rd_kafka_crypto_wipe(void *p, size_t n) {
        volatile unsigned char *v = p;
        while (n--)
                *v++ = 0;
}
int rd_kafka_crypto_digest(rd_kafka_crypto_hash_t h,
                           const void *in,
                           size_t n,
                           unsigned char *out) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out ||
            (!in && n))
                return -1;
        return rd_kafka_crypto_ops->digest(h, in, n, out);
}
int rd_kafka_crypto_hmac(rd_kafka_crypto_hash_t h,
                         const void *key,
                         size_t kn,
                         const void *in,
                         size_t n,
                         unsigned char *out) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out ||
            (!key && kn) || (!in && n))
                return -1;
        return rd_kafka_crypto_ops->hmac(h, key, kn, in, n, out);
}
int rd_kafka_crypto_pbkdf2(rd_kafka_crypto_hash_t h,
                           const void *key,
                           size_t kn,
                           const void *salt,
                           size_t sn,
                           uint64_t it,
                           unsigned char *out,
                           size_t n) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out ||
            (!key && kn) || (!salt && sn) || !it || !n)
                return -1;
        return rd_kafka_crypto_ops->pbkdf2(h, key, kn, salt, sn, it, out, n);
}
int rd_kafka_crypto_random(void *out, size_t n) {
        if (!rd_kafka_crypto_ops || (!out && n))
                return -1;
        return rd_kafka_crypto_ops->random(out, n);
}
rd_kafka_crypto_key_t *rd_kafka_crypto_key_load(const void *pem,
                                                size_t n,
                                                const char *password,
                                                char *e,
                                                size_t en) {
        if (!rd_kafka_crypto_ops || !pem || !n) {
                if (en)
                        snprintf(e, en, "Crypto key import is unavailable");
                return NULL;
        }
        return rd_kafka_crypto_ops->key_load(pem, n, password, e, en);
}
int rd_kafka_crypto_sign(rd_kafka_crypto_key_t *key,
                         rd_kafka_crypto_signature_t alg,
                         const void *in,
                         size_t n,
                         unsigned char **out,
                         size_t *on,
                         char *e,
                         size_t en) {
        if (!out || !on)
                return -1;
        *out = NULL;
        *on  = 0;
        if (!rd_kafka_crypto_ops || !key || (!in && n)) {
                if (en)
                        snprintf(e, en, "Crypto signing is unavailable");
                return -1;
        }
        return rd_kafka_crypto_ops->sign(key, alg, in, n, out, on, e, en);
}
void rd_kafka_crypto_key_destroy(rd_kafka_crypto_key_t *key) {
        if (key && rd_kafka_crypto_ops)
                rd_kafka_crypto_ops->key_destroy(key);
}


/**
 * @name Unit tests
 *
 * Known-answer vectors from FIPS 180-4, RFC 4231 and RFC 6070/7914, plus a
 * fixed RS256 signature (PKCS#1 v1.5 is deterministic). ES256 is randomized,
 * so OpenSSL builds verify it independently; other backends check the
 * RFC 7518 R || S length only.
 */
#include "rdunittest.h"
#if WITH_CRYPTO_OPENSSL
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

static const char ut_rsa_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQM7CAaDYZroNy\n"
    "LG0SS5Ynz8r5hq/objDGZ0WjrslEVGAIpYMNxU+3/Yk/QEpLNheamludFgj9PzaL\n"
    "p0OwaQZdzJUzguN51qPXWLml+XFv7VuAmzK7lJXemz6lIqVZ0SdvAyji/8A88m7G\n"
    "pTkLDf8BaX2urIk5ngAudkJZEcmSo1khbN9a0bn5h/85naxMq/v7DpSthcC7KmNQ\n"
    "3SOlRU9LUrHLJ7INM9GjJv/5tGrZ+VeI5n72anylBOCeCQ/P2xdyvMnVMmKmenya\n"
    "0yyMZ14wFslR3FFd2fo3H4HnGFw5ob19qOYUp1xkIE8hX4DPwOxM3hb3gbFqbEdb\n"
    "zZ/ZfMbLAgMBAAECggEACzQE1twEsTwVQaMHWXkswsapJuUq+QhY4owzEJw6o00g\n"
    "/8YcN7T61a00Ye1tMf/epEiTDnBdmnb40en1t/vmxkxYaPWtlORKW6+gCcDS7FFq\n"
    "35A6WiKkL97Nr6geGqepBg22+QQHDaCD+ndwito9cw+AnlIVbj7ExrtBVbah0JyV\n"
    "mu/XmfIwa/pBhbgXnKXrKpq+SHuNHoNIyBEMXqMlv2ks706OoIdF8Sl/cGJOU1ib\n"
    "EfCNe7O43G9repY6MDpnUw1/9WX2j7IoC7HIF2cMV0Pm1L0lO1mpc+/eqCmZsJWH\n"
    "pNsMuVq2Okhp92wIKcJCEav/VkJF9cQI5LmEVxHXWQKBgQD+5nMc31pfpcanMbV1\n"
    "u17g7ug0HohIS5p8Ej/3Rp4v2lk0RasD32ikJZL6jo3UNqiHl3HxSBAIQ4nuNv0U\n"
    "3HfXaQucsb9DTeXh2ZWBV+t9rFV+2on/NMmC2XYc2hvbCkcGtd4HVSQP8SiunE1G\n"
    "EruTcwmZWQZWtOttWIpauWB6IwKBgQDRGai+LalXxjjLyFfo+/mHLGNKgpa1FTDI\n"
    "6VRLWoOGMVooznGdXgoCX/bsDklF1KXTNOKu1nI5bHUulPJxm4sQT5y0RzUhedlC\n"
    "mehsb0+BP+YpR+Iz7PcAFoiA0LcdwVLI5pgfJS8xhHO1AMUqYj+wL4WCNctfWiUn\n"
    "oeKuFsTnOQKBgAx1MN0RYXZZQMs9F7RIUwvFQV4CvABkiYlUzwGD1wlZr5Bpc0E+\n"
    "MvwKxhMu0mmzviraUPxM3FO7EUuuLlJNsCG8BZBD86gTb4/JNZBbvqumt4r6nVH2\n"
    "v36AqFAirMfYyb3fN5m+JIQO8kEObIxnL/m13ps7CZ9FOlhewmxKsRdnAoGARfJi\n"
    "azPVGSKa7zhWh/56S0iC8nLavTqYdizvYMGni6VItqvQf8bsbDzz2aUxx6VJz2w6\n"
    "hCgCT8lDLdDvhSd2Dn/DON81G7yp+8iGYnedzeu1L4v3VE1pluLyyLyI9PAtpDzX\n"
    "GFwU/GiFWEAotHPnQCW1cIhUPtJl6WsS7A970KkCgYEAl+4+FJopTNaMRghUKUNX\n"
    "rmG4hY51IZjpsqfV7ByaqZ84V+R2HD4Dt/0IdRGJCzMyc0sdy4GL6RnV+rnUpdTl\n"
    "O++jEJqbCPemtWndakeVX3f/p47ZbWXpXJ9QEca3h2WMtpd2txsxnjvIJu2qpTYr\n"
    "6RD32qMY2AYKyF2JKlM6FOc=\n"
    "-----END PRIVATE KEY-----\n";

static const char ut_ec_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMbixBe7yizrdEN4K\n"
    "xgFU4ZPfSFtluOzV03x2IdhgA8+hRANCAARn5fvFGJrHphVAXdObOkM4lCpJ43mi\n"
    "Gmduw82WgpGF5leCDcQ0TzgMDsDC+DgGLkIUffnGMuP6FrlqV2IkESkk\n"
    "-----END PRIVATE KEY-----\n";

static const char ut_rs256_sig[] =
    "87234650cf120bc8cde22c12d9b6a7efe89571a19470f49c3dfd3f266d13"
    "193a62d5f422914bf67782a808a53136cef8aa5575826aedda262c8abfec"
    "48c2c18cabb5ae29218bd2f75632ef7df84f8b8c637baf4a59e4cf72206a"
    "34c188a9811bc10add70607fca29cb4dea23317c64a2b3882941fea5df28"
    "5facda056929d65094bdbd727da641815a72d552c2a58b57ad0f223d971c"
    "dae3c7f92d7a0c3f23215a7d6c848dff4b1bb146b3749d11bb45f7079c1b"
    "4a47c7903f4c3ac7c588da822920475c20f215f2b935cf2db9c1aaa3a304"
    "055c02811636fe9589c1e385c5c74b00707afc52e1911e12dba285584439"
    "a6f2c885dc2befaa69274e69b34f4482";

static const char ut_message[] = "backend-signature-vector";

static rd_bool_t
ut_hex_eq(const unsigned char *p, size_t n, const char *expected) {
        static const char digits[] = "0123456789abcdef";
        size_t i;
        if (strlen(expected) != n * 2)
                return rd_false;
        for (i = 0; i < n; i++)
                if (expected[2 * i] != digits[p[i] >> 4] ||
                    expected[2 * i + 1] != digits[p[i] & 15])
                        return rd_false;
        return rd_true;
}

static int ut_crypto_sign_rs256(void) {
        rd_kafka_crypto_key_t *key;
        unsigned char *sig = NULL;
        size_t size        = 0;
        char errstr[256];
        int r;

        key = rd_kafka_crypto_key_load(ut_rsa_key, strlen(ut_rsa_key), NULL,
                                       errstr, sizeof(errstr));
        RD_UT_ASSERT(key, "key import failed: %s", errstr);

        r = rd_kafka_crypto_sign(key, RD_KAFKA_CRYPTO_RS256, ut_message,
                                 strlen(ut_message), &sig, &size, errstr,
                                 sizeof(errstr));
        rd_kafka_crypto_key_destroy(key);
        RD_UT_ASSERT(!r, "signing failed: %s", errstr);
        r = size == 256 && ut_hex_eq(sig, size, ut_rs256_sig);
        rd_free(sig);
        RD_UT_ASSERT(r, "RS256 signature is wrong (%" PRIusz " bytes)", size);
        return 0;
}

#if WITH_CRYPTO_OPENSSL
static rd_bool_t ut_es256_verify(const unsigned char *sig) {
        BIO *bio = BIO_new_mem_buf(ut_ec_key, -1);
        EVP_PKEY *pkey =
            bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
        ECDSA_SIG *esig    = ECDSA_SIG_new();
        EVP_MD_CTX *ctx    = EVP_MD_CTX_new();
        unsigned char *der = NULL;
        int der_len        = -1;
        rd_bool_t ok       = rd_false;
        if (pkey && esig && ctx &&
            ECDSA_SIG_set0(esig, BN_bin2bn(sig, 32, NULL),
                           BN_bin2bn(sig + 32, 32, NULL)) == 1)
                der_len = i2d_ECDSA_SIG(esig, &der);
        if (der_len > 0 &&
            EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, der, (size_t)der_len,
                             (const unsigned char *)ut_message,
                             strlen(ut_message)) == 1)
                ok = rd_true;
        OPENSSL_free(der);
        EVP_MD_CTX_free(ctx);
        ECDSA_SIG_free(esig);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return ok;
}
#endif

static int ut_crypto_sign_es256(void) {
        rd_kafka_crypto_key_t *key;
        unsigned char *sig = NULL;
        size_t size        = 0;
        char errstr[256];
        int r;

        key = rd_kafka_crypto_key_load(ut_ec_key, strlen(ut_ec_key), NULL,
                                       errstr, sizeof(errstr));
        RD_UT_ASSERT(key, "key import failed: %s", errstr);
        r = rd_kafka_crypto_sign(key, RD_KAFKA_CRYPTO_ES256, ut_message,
                                 strlen(ut_message), &sig, &size, errstr,
                                 sizeof(errstr));
        rd_kafka_crypto_key_destroy(key);
        RD_UT_ASSERT(!r, "signing failed: %s", errstr);
        r = size == 64;
#if WITH_CRYPTO_OPENSSL
        r = r && ut_es256_verify(sig);
#endif
        rd_free(sig);
        RD_UT_ASSERT(r, "ES256 signature is wrong (%" PRIusz " bytes)", size);

        key = rd_kafka_crypto_key_load(ut_rsa_key, strlen(ut_rsa_key), NULL,
                                       errstr, sizeof(errstr));
        RD_UT_ASSERT(key, "key import failed: %s", errstr);
        sig = NULL;
        r   = rd_kafka_crypto_sign(key, RD_KAFKA_CRYPTO_ES256, ut_message,
                                   strlen(ut_message), &sig, &size, errstr,
                                   sizeof(errstr));
        rd_kafka_crypto_key_destroy(key);
        RD_UT_ASSERT(r == -1 && !sig && !size,
                     "ES256 with an RSA key must fail");
        return 0;
}

int unittest_crypto(void) {
        unsigned char out[64], key[20], random1[32], random2[32];
        char errstr[128];

        RD_UT_ASSERT(rd_kafka_crypto_ops, "no crypto backend");
        RD_UT_SAY("crypto backend: %s", rd_kafka_crypto_ops->name);

        RD_UT_ASSERT(
            !rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA1, "abc", 3, out) &&
                ut_hex_eq(out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            "SHA-1");
        RD_UT_ASSERT(
            !rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA256, "abc", 3, out) &&
                ut_hex_eq(out, 32,
                          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410"
                          "ff61f20015ad"),
            "SHA-256");
        RD_UT_ASSERT(
            !rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA512, "abc", 3, out) &&
                ut_hex_eq(out, 64,
                          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9e"
                          "eee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423"
                          "643ce80e2a9ac94fa54ca49f"),
            "SHA-512");
        RD_UT_ASSERT(
            !rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA256, NULL, 0, out) &&
                ut_hex_eq(out, 32,
                          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495"
                          "991b7852b855"),
            "SHA-256 of empty input");
        RD_UT_ASSERT(rd_kafka_crypto_digest((rd_kafka_crypto_hash_t)99, "x", 1,
                                            out) == -1,
                     "unknown hash must fail");

        memset(key, 0x0b, sizeof(key));
        RD_UT_ASSERT(
            !rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA256, key, 20, "Hi There",
                                  8, out) &&
                ut_hex_eq(out, 32,
                          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9"
                          "376c2e32cff7"),
            "HMAC-SHA-256");
        RD_UT_ASSERT(
            !rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA512, key, 20, "Hi There",
                                  8, out) &&
                ut_hex_eq(out, 64,
                          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0"
                          "b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914e"
                          "eb61f1702e696c203a126854"),
            "HMAC-SHA-512");
        RD_UT_ASSERT(
            !rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA256, NULL, 0, NULL, 0,
                                  out) &&
                ut_hex_eq(out, 32,
                          "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c7"
                          "12144292c5ad"),
            "HMAC-SHA-256 with empty key and input");

        RD_UT_ASSERT(
            !rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA1, "password", 8, "salt",
                                    4, 2, out, 20) &&
                ut_hex_eq(out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            "PBKDF2-HMAC-SHA-1");
        RD_UT_ASSERT(
            !rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA256, "password", 8,
                                    "salt", 4, 1, out, 32) &&
                ut_hex_eq(out, 32,
                          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805"
                          "987cb70be17b"),
            "PBKDF2-HMAC-SHA-256");
        RD_UT_ASSERT(
            !rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA512, "password", 8,
                                    "salt", 4, 1, out, 64) &&
                ut_hex_eq(out, 64,
                          "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513"
                          "554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7"
                          "d68b1da55e63f73b60a57fce"),
            "PBKDF2-HMAC-SHA-512");
        RD_UT_ASSERT(rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA256, "x", 1, "s",
                                            1, 0, out, 32) == -1,
                     "PBKDF2 with zero iterations must fail");

        RD_UT_ASSERT(!rd_kafka_crypto_random(random1, sizeof(random1)) &&
                         !rd_kafka_crypto_random(random2, sizeof(random2)) &&
                         memcmp(random1, random2, sizeof(random1)),
                     "random bytes");
        RD_UT_ASSERT(!rd_kafka_crypto_random(NULL, 0), "empty random request");

        RD_UT_ASSERT(!rd_kafka_crypto_key_load("invalid key", 11, NULL, errstr,
                                               sizeof(errstr)),
                     "invalid key must fail to load");
        if (ut_crypto_sign_rs256() || ut_crypto_sign_es256())
                return 1;

        RD_UT_PASS();
}
