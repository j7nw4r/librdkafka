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
typedef enum { RD_KAFKA_CRYPTO_RS256, RD_KAFKA_CRYPTO_ES256 }
    rd_kafka_crypto_signature_t;
typedef struct rd_kafka_crypto_key_s rd_kafka_crypto_key_t;

typedef struct rd_kafka_crypto_ops_s {
        const char *name;
        void (*global_init)(void);
        void (*global_term)(void);
        int (*digest)(rd_kafka_crypto_hash_t, const void *, size_t, unsigned char *);
        int (*hmac)(rd_kafka_crypto_hash_t, const void *, size_t, const void *, size_t, unsigned char *);
        int (*pbkdf2)(rd_kafka_crypto_hash_t, const void *, size_t, const void *, size_t, uint64_t, unsigned char *, size_t);
        int (*random)(void *, size_t);
        rd_kafka_crypto_key_t *(*key_load)(const void *, size_t, const char *, char *, size_t);
        int (*sign)(rd_kafka_crypto_key_t *, rd_kafka_crypto_signature_t, const void *, size_t, unsigned char **, size_t *, char *, size_t);
        void (*key_destroy)(rd_kafka_crypto_key_t *);
} rd_kafka_crypto_ops_t;
extern const rd_kafka_crypto_ops_t rd_kafka_crypto_openssl_ops;
extern const rd_kafka_crypto_ops_t rd_kafka_crypto_bcrypt_ops;
extern const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops;
void rd_kafka_crypto_init(void);
void rd_kafka_crypto_term(void);
size_t rd_kafka_crypto_digest_size(rd_kafka_crypto_hash_t);
int rd_kafka_crypto_digest(rd_kafka_crypto_hash_t, const void *, size_t, unsigned char *);
int rd_kafka_crypto_hmac(rd_kafka_crypto_hash_t, const void *, size_t, const void *, size_t, unsigned char *);
int rd_kafka_crypto_pbkdf2(rd_kafka_crypto_hash_t, const void *, size_t, const void *, size_t, uint64_t, unsigned char *, size_t);
/* Security randomness: failure is returned directly, never another provider. */
int rd_kafka_crypto_random(void *, size_t);
rd_kafka_crypto_key_t *rd_kafka_crypto_key_load(const void *, size_t, const char *, char *, size_t);
/* Allocated signatures are RSA PKCS#1 v1.5 or ES256 JOSE fixed-width r||s. */
int rd_kafka_crypto_sign(rd_kafka_crypto_key_t *, rd_kafka_crypto_signature_t, const void *, size_t, unsigned char **, size_t *, char *, size_t);
void rd_kafka_crypto_key_destroy(rd_kafka_crypto_key_t *);
void rd_kafka_crypto_wipe(void *, size_t);
#endif
