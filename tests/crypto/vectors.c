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
/* Backend-neutral known-answer and JOSE signature contract tests. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "rdkafka_crypto.h"
#include "rdbase64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
        do {                                                                   \
                if (!(x)) {                                                    \
                        fprintf(stderr,                                        \
                                "crypto check failed at line %d: %s\n",        \
                                __LINE__, #x);                                 \
                        return 1;                                              \
                }                                                              \
        } while (0)
static int hex(const unsigned char *p, size_t n, const char *expected) {
        static const char digits[] = "0123456789abcdef";
        size_t i;
        if (strlen(expected) != n * 2)
                return 0;
        for (i = 0; i < n; i++)
                if (expected[2 * i] != digits[p[i] >> 4] ||
                    expected[2 * i + 1] != digits[p[i] & 15])
                        return 0;
        return 1;
}
static int codecs(void) {
        const char *plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
        const char *encoded[] = {"",         "Zg==",     "Zm8=",    "Zm9v",
                                 "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
        const char *bad[]     = {
            "A",    "AA=",  "A===",  "====",       "AA=A", "Zg=A",
            "Zh==", "Zm9=", "Zm9v=", "Zm9v\nAAAA", "Zg--"};
        size_t i;
        for (i = 0; i < sizeof(plain) / sizeof(*plain); i++) {
                rd_chariov_t in = {.ptr  = (char *)plain[i],
                                   .size = strlen(plain[i])},
                             out, decoded;
                rd_base64_encode(&in, &out);
                CHECK(out.ptr && strcmp(out.ptr, encoded[i]) == 0);
                CHECK(!rd_base64_decode(&out, &decoded));
                CHECK(decoded.size == in.size &&
                      !memcmp(decoded.ptr, in.ptr, in.size));
                free(out.ptr);
                free(decoded.ptr);
        }
        for (i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
                rd_chariov_t in = {.ptr  = (char *)bad[i],
                                   .size = strlen(bad[i])},
                             out;
                CHECK(rd_base64_decode(&in, &out) == -1 && out.ptr == NULL);
        }
        {
                rd_chariov_t in = {.ptr = " \tZg==\r\n", .size = 8}, out;
                CHECK(!rd_base64_decode(&in, &out) && out.size == 1 &&
                      out.ptr[0] == 'f');
                free(out.ptr);
        }
        {
                unsigned char bytes[] = {251, 255};
                rd_chariov_t in       = {.ptr = (char *)bytes, .size = 2};
                char *out             = rd_base64_encode_str_urlsafe(&in);
                CHECK(out && !strcmp(out, "-_8"));
                free(out);
        }
        return 0;
}
static int signatures(int argc, char **argv) {
        const char *message = "backend-signature-vector";
        int i;
        char error[256];
        for (i = 0; i < 2; i++) {
                FILE *fp = fopen(argv[i + 1], "rb");
                long n;
                char *pem;
                rd_kafka_crypto_key_t *key;
                unsigned char *sig = NULL;
                size_t size        = 0;
                char path[2048];
                CHECK(fp && fseek(fp, 0, SEEK_END) == 0);
                n = ftell(fp);
                CHECK(n > 0 && n < 1024 * 1024 && fseek(fp, 0, SEEK_SET) == 0);
                pem = malloc((size_t)n);
                CHECK(pem && fread(pem, 1, (size_t)n, fp) == (size_t)n);
                fclose(fp);
                key = rd_kafka_crypto_key_load(pem, (size_t)n, NULL, error,
                                               sizeof(error));
                rd_kafka_crypto_wipe(pem, (size_t)n);
                free(pem);
                if (!key)
                        fprintf(stderr, "key import: %s\n", error);
                CHECK(key);
                CHECK(!rd_kafka_crypto_sign(
                    key, i ? RD_KAFKA_CRYPTO_ES256 : RD_KAFKA_CRYPTO_RS256,
                    message, strlen(message), &sig, &size, error,
                    sizeof(error)));
                CHECK(size == (i ? 64 : 256));
                snprintf(path, sizeof(path), "%s/%s.bin", argv[3],
                         i ? "es256" : "rs256");
                fp = fopen(path, "wb");
                CHECK(fp && fwrite(sig, 1, size, fp) == size &&
                      fclose(fp) == 0);
                free(sig);
                sig = NULL;
                CHECK(rd_kafka_crypto_sign(key,
                                           i ? RD_KAFKA_CRYPTO_RS256
                                             : RD_KAFKA_CRYPTO_ES256,
                                           message, strlen(message), &sig,
                                           &size, error, sizeof(error)) == -1 &&
                      sig == NULL && size == 0);
                rd_kafka_crypto_key_destroy(key);
        }
        (void)argc;
        return 0;
}
int main(int argc, char **argv) {
        unsigned char out[64], key[20], random1[32], random2[32];
        rd_kafka_crypto_init();
        CHECK(rd_kafka_crypto_ops);
        printf("crypto backend: %s\n", rd_kafka_crypto_ops->name);
        CHECK(!rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA1, "abc", 3, out) &&
              hex(out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));
        CHECK(!rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA256, "abc", 3, out) &&
              hex(out, 32,
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f200"
                  "15ad"));
        CHECK(!rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA512, "abc", 3, out) &&
              hex(out, 64,
                  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55"
                  "d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94f"
                  "a54ca49f"));
        memset(key, 0x0b, sizeof(key));
        CHECK(!rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA256, key, 20, "Hi There",
                                    8, out) &&
              hex(out, 32,
                  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32"
                  "cff7"));
        CHECK(!rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA512, key, 20, "Hi There",
                                    8, out) &&
              hex(out, 64,
                  "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e1"
                  "7cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c20"
                  "3a126854"));
        CHECK(!rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA1, "password", 8,
                                      "salt", 4, 2, out, 20) &&
              hex(out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
        CHECK(!rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA256, "password", 8,
                                      "salt", 4, 1, out, 32) &&
              hex(out, 32,
                  "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70b"
                  "e17b"));
        CHECK(!rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA512, "password", 8,
                                      "salt", 4, 1, out, 64) &&
              hex(out, 64,
                  "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8c"
                  "f252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b"
                  "60a57fce"));
        CHECK(rd_kafka_crypto_pbkdf2(RD_KAFKA_CRYPTO_SHA256, "x", 1, "s", 1, 0,
                                     out, 32) == -1);
        CHECK(rd_kafka_crypto_digest((rd_kafka_crypto_hash_t)99, "x", 1, out) ==
              -1);
        CHECK(!rd_kafka_crypto_digest(RD_KAFKA_CRYPTO_SHA256, NULL, 0, out) &&
              hex(out, 32,
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852"
                  "b855"));
        CHECK(!rd_kafka_crypto_hmac(RD_KAFKA_CRYPTO_SHA256, NULL, 0, NULL, 0,
                                    out) &&
              hex(out, 32,
                  "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292"
                  "c5ad"));
        {
                char error[128];
                CHECK(!rd_kafka_crypto_key_load("invalid key", 11, NULL, error,
                                                sizeof(error)));
        }
        CHECK(!rd_kafka_crypto_random(random1, sizeof(random1)) &&
              !rd_kafka_crypto_random(random2, sizeof(random2)) &&
              memcmp(random1, random2, sizeof(random1)));
        CHECK(!rd_kafka_crypto_random(NULL, 0));
        CHECK(!codecs());
        if (argc == 4)
                CHECK(!signatures(argc, argv));
        else
                CHECK(argc == 1);
        rd_kafka_crypto_term();
        puts("PASS hash/HMAC/PBKDF2/RNG/Base64 and requested signature checks");
        return 0;
}
