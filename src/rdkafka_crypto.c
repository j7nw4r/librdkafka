#include "rd.h"
#include "rdkafka_crypto.h"
#if WITH_CRYPTO_OPENSSL
const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops = &rd_kafka_crypto_openssl_ops;
#elif WITH_CRYPTO_BCRYPT
const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops = &rd_kafka_crypto_bcrypt_ops;
#else
const rd_kafka_crypto_ops_t *const rd_kafka_crypto_ops = NULL;
#endif
void rd_kafka_crypto_init(void) { if(rd_kafka_crypto_ops)rd_kafka_crypto_ops->global_init(); }
void rd_kafka_crypto_term(void) { if(rd_kafka_crypto_ops)rd_kafka_crypto_ops->global_term(); }
size_t rd_kafka_crypto_digest_size(rd_kafka_crypto_hash_t h) {
        switch (h) { case RD_KAFKA_CRYPTO_SHA1: return 20; case RD_KAFKA_CRYPTO_SHA256: return 32; case RD_KAFKA_CRYPTO_SHA512: return 64; default: return 0; }
}
void rd_kafka_crypto_wipe(void *p, size_t n) {
        volatile unsigned char *v = p;
        while (n--) *v++ = 0;
}
int rd_kafka_crypto_digest(rd_kafka_crypto_hash_t h, const void *in, size_t n, unsigned char *out) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out || (!in && n)) return -1;
        return rd_kafka_crypto_ops->digest(h,in,n,out);
}
int rd_kafka_crypto_hmac(rd_kafka_crypto_hash_t h, const void *key, size_t kn, const void *in, size_t n, unsigned char *out) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out || (!key && kn) || (!in && n)) return -1;
        return rd_kafka_crypto_ops->hmac(h,key,kn,in,n,out);
}
int rd_kafka_crypto_pbkdf2(rd_kafka_crypto_hash_t h, const void *key, size_t kn, const void *salt, size_t sn, uint64_t it, unsigned char *out, size_t n) {
        if (!rd_kafka_crypto_ops || !rd_kafka_crypto_digest_size(h) || !out || (!key && kn) || (!salt && sn) || !it || !n) return -1;
        return rd_kafka_crypto_ops->pbkdf2(h,key,kn,salt,sn,it,out,n);
}
int rd_kafka_crypto_random(void *out, size_t n) {
        if (!rd_kafka_crypto_ops || (!out && n)) return -1;
        return rd_kafka_crypto_ops->random(out,n);
}
rd_kafka_crypto_key_t *rd_kafka_crypto_key_load(const void *pem, size_t n, const char *password, char *e, size_t en) {
        if (!rd_kafka_crypto_ops || !pem || !n) { if (en) snprintf(e,en,"Crypto key import is unavailable"); return NULL; }
        return rd_kafka_crypto_ops->key_load(pem,n,password,e,en);
}
int rd_kafka_crypto_sign(rd_kafka_crypto_key_t *key, rd_kafka_crypto_signature_t alg, const void *in, size_t n, unsigned char **out, size_t *on, char *e, size_t en) {
        if (!out || !on) return -1;
        *out=NULL; *on=0;
        if (!rd_kafka_crypto_ops || !key || (!in && n)) { if(en)snprintf(e,en,"Crypto signing is unavailable"); return -1; }
        return rd_kafka_crypto_ops->sign(key,alg,in,n,out,on,e,en);
}
void rd_kafka_crypto_key_destroy(rd_kafka_crypto_key_t *key) { if (key && rd_kafka_crypto_ops) rd_kafka_crypto_ops->key_destroy(key); }
