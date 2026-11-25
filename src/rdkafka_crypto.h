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
/* Private crypto services. No native provider types cross this interface. */
#ifndef _RDKAFKA_CRYPTO_H_
#define _RDKAFKA_CRYPTO_H_
#include <stddef.h>
#include <stdint.h>
#define RD_KAFKA_CRYPTO_MAX_DIGEST_SIZE 64

typedef enum {
        RD_KAFKA_CRYPTO_SHA1,
        RD_KAFKA_CRYPTO_SHA256,
        RD_KAFKA_CRYPTO_SHA512
} rd_kafka_crypto_hash_t;
typedef enum {
        RD_KAFKA_CRYPTO_RS256,
        RD_KAFKA_CRYPTO_ES256
} rd_kafka_crypto_signature_t;
typedef struct rd_kafka_crypto_key_s rd_kafka_crypto_key_t;

typedef struct rd_kafka_crypto_ops_s {
        const char *name;
        void (*global_init)(void);
        void (*global_term)(void);
        void (*thread_term)(void);
        int (*digest)(rd_kafka_crypto_hash_t,
                      const void *,
                      size_t,
                      unsigned char *);
        int (*hmac)(rd_kafka_crypto_hash_t,
                    const void *,
                    size_t,
                    const void *,
                    size_t,
                    unsigned char *);
        int (*pbkdf2)(rd_kafka_crypto_hash_t,
                      const void *,
                      size_t,
                      const void *,
                      size_t,
                      uint64_t,
                      unsigned char *,
                      size_t);
        int (*random)(void *, size_t);
        rd_kafka_crypto_key_t *(
            *key_load)(const void *, size_t, const char *, char *, size_t);
        int (*sign)(rd_kafka_crypto_key_t *,
                    rd_kafka_crypto_signature_t,
                    const void *,
                    size_t,
                    unsigned char **,
                    size_t *,
                    char *,
                    size_t);
        void (*key_destroy)(rd_kafka_crypto_key_t *);
} rd_kafka_crypto_ops_t;
extern const rd_kafka_crypto_ops_t rd_kafka_crypto_openssl_ops;
extern const rd_kafka_crypto_ops_t rd_kafka_crypto_bcrypt_ops;
extern const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops;
void rd_kafka_crypto_init(void);
void rd_kafka_crypto_term(void);
void rd_kafka_crypto_thread_term(void);
size_t rd_kafka_crypto_digest_size(rd_kafka_crypto_hash_t);
int rd_kafka_crypto_digest(rd_kafka_crypto_hash_t,
                           const void *,
                           size_t,
                           unsigned char *);
int rd_kafka_crypto_hmac(rd_kafka_crypto_hash_t,
                         const void *,
                         size_t,
                         const void *,
                         size_t,
                         unsigned char *);
int rd_kafka_crypto_pbkdf2(rd_kafka_crypto_hash_t,
                           const void *,
                           size_t,
                           const void *,
                           size_t,
                           uint64_t,
                           unsigned char *,
                           size_t);
/* Security randomness: failure is returned directly, never another provider. */
int rd_kafka_crypto_random(void *, size_t);
rd_kafka_crypto_key_t *
rd_kafka_crypto_key_load(const void *, size_t, const char *, char *, size_t);
/* RS256 gives a PKCS#1 v1.5 signature and ES256 the 64-byte R || S form of
 * RFC 7518 section 3.4. The caller frees *out with rd_free(). */
int rd_kafka_crypto_sign(rd_kafka_crypto_key_t *,
                         rd_kafka_crypto_signature_t,
                         const void *,
                         size_t,
                         unsigned char **,
                         size_t *,
                         char *,
                         size_t);
void rd_kafka_crypto_key_destroy(rd_kafka_crypto_key_t *);
void rd_kafka_crypto_wipe(void *, size_t);
#endif
