/* Windows CNG implementation: BCrypt primitives and ephemeral NCrypt keys. */
#ifndef _WIN32
#error "BCrypt crypto backend requires Windows"
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include "rdkafka_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
struct rd_kafka_crypto_key_s { NCRYPT_PROV_HANDLE provider; NCRYPT_KEY_HANDLE key; };
static LPCWSTR algorithm(rd_kafka_crypto_hash_t h) {
        switch(h){case RD_KAFKA_CRYPTO_SHA1:return BCRYPT_SHA1_ALGORITHM;case RD_KAFKA_CRYPTO_SHA256:return BCRYPT_SHA256_ALGORITHM;case RD_KAFKA_CRYPTO_SHA512:return BCRYPT_SHA512_ALGORITHM;default:return NULL;}
}
static int hash_data(rd_kafka_crypto_hash_t h,const void *key,size_t kn,const void *data,size_t n,unsigned char *out,int mac) {
        BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;unsigned char *object=NULL;DWORD object_size=0,got=0;const unsigned char *in=data;int ok=0;
        if(kn>UINT32_MAX||!algorithm(h))return -1;
        if(BCryptOpenAlgorithmProvider(&alg,algorithm(h),MS_PRIMITIVE_PROVIDER,mac?BCRYPT_ALG_HANDLE_HMAC_FLAG:0)<0)goto done;
        if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&object_size,sizeof(object_size),&got,0)<0)goto done;
        object=malloc(object_size);if(!object)goto done;
        if(BCryptCreateHash(alg,&hash,object,object_size,(PUCHAR)key,(ULONG)kn,0)<0)goto done;
        while(n){ULONG chunk=n>UINT32_MAX?UINT32_MAX:(ULONG)n;if(BCryptHashData(hash,(PUCHAR)in,chunk,0)<0)goto done;in+=chunk;n-=chunk;}
        if(BCryptFinishHash(hash,out,(ULONG)rd_kafka_crypto_digest_size(h),0)<0)goto done;
        ok=1;
done:if(hash)BCryptDestroyHash(hash);if(object){SecureZeroMemory(object,object_size);free(object);}if(alg)BCryptCloseAlgorithmProvider(alg,0);return ok?0:-1;
}
static int digest(rd_kafka_crypto_hash_t h,const void *p,size_t n,unsigned char *out){return hash_data(h,NULL,0,p,n,out,0);}
static int hmac(rd_kafka_crypto_hash_t h,const void *key,size_t kn,const void *p,size_t n,unsigned char *out){return hash_data(h,kn?key:"",kn,p,n,out,1);}
static int pbkdf2(rd_kafka_crypto_hash_t h,const void *key,size_t kn,const void *salt,size_t sn,uint64_t it,unsigned char *out,size_t n){BCRYPT_ALG_HANDLE alg=NULL;NTSTATUS status;if(kn>UINT32_MAX||sn>UINT32_MAX||n>UINT32_MAX||!algorithm(h))return -1;if(BCryptOpenAlgorithmProvider(&alg,algorithm(h),MS_PRIMITIVE_PROVIDER,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)return -1;status=BCryptDeriveKeyPBKDF2(alg,(PUCHAR)key,(ULONG)kn,(PUCHAR)salt,(ULONG)sn,it,out,(ULONG)n,0);BCryptCloseAlgorithmProvider(alg,0);return status>=0?0:-1;}
static int random_bytes(void *p,size_t n){unsigned char *out=p;while(n){ULONG chunk=n>UINT32_MAX?UINT32_MAX:(ULONG)n;if(BCryptGenRandom(NULL,out,chunk,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return -1;out+=chunk;n-=chunk;}return 0;}
static void key_destroy(rd_kafka_crypto_key_t *k){if(k->key)NCryptFreeObject(k->key);if(k->provider)NCryptFreeObject(k->provider);free(k);}
static rd_kafka_crypto_key_t *key_load(const void *pem,size_t n,const char *password,char *e,size_t en){
        rd_kafka_crypto_key_t *key=NULL;BYTE *der=NULL;DWORD size=0;SECURITY_STATUS status=NTE_BAD_DATA;const char *stage="PEM decoding";int is_pem=n>=10&&!memcmp(pem,"-----BEGIN",10);
        if(n>UINT32_MAX||(password&&*password)){snprintf(e,en,"BCrypt requires an unencrypted PKCS#8 private key");return NULL;}
        if(is_pem){
                const char *tag="-----BEGIN PRIVATE KEY-----";
                if(n<strlen(tag)||memcmp(pem,tag,strlen(tag))||!CryptStringToBinaryA(pem,(DWORD)n,CRYPT_STRING_BASE64HEADER,NULL,&size,NULL,NULL))goto fail;
                der=malloc(size);if(!der||!CryptStringToBinaryA(pem,(DWORD)n,CRYPT_STRING_BASE64HEADER,der,&size,NULL,NULL))goto fail;
        }else{size=(DWORD)n;der=malloc(size);if(!der)goto fail;memcpy(der,pem,size);}
        key=calloc(1,sizeof(*key));if(!key)goto fail;
        stage="storage provider";status=NCryptOpenStorageProvider(&key->provider,MS_KEY_STORAGE_PROVIDER,0);if(status!=ERROR_SUCCESS)goto fail;
        stage="PKCS#8 import";status=NCryptImportKey(key->provider,0,NCRYPT_PKCS8_PRIVATE_KEY_BLOB,NULL,&key->key,der,size,NCRYPT_SILENT_FLAG);if(status!=ERROR_SUCCESS)goto fail;
        SecureZeroMemory(der,size);free(der);return key;
fail:if(der){SecureZeroMemory(der,size);free(der);}if(key)key_destroy(key);snprintf(e,en,"BCrypt private key %s failed (0x%08lx); use unencrypted PKCS#8 PEM/DER",stage,(unsigned long)(ULONG)status);return NULL;
}
static int sign_data(rd_kafka_crypto_key_t *key,rd_kafka_crypto_signature_t sigalg,const void *data,size_t n,unsigned char **out,size_t *on,char *e,size_t en){
        WCHAR group[64]={0},name[64]={0};DWORD got=0,bits=0,size=0,flags=0;unsigned char hash[32],*sig=NULL;BCRYPT_PKCS1_PADDING_INFO padding={BCRYPT_SHA256_ALGORITHM};void *pad=NULL;int ok=0;
        if(NCryptGetProperty(key->key,NCRYPT_ALGORITHM_GROUP_PROPERTY,(PBYTE)group,sizeof(group),&got,0)!=ERROR_SUCCESS)goto done;
        if(sigalg==RD_KAFKA_CRYPTO_RS256){if(wcscmp(group,NCRYPT_RSA_ALGORITHM_GROUP))goto done;pad=&padding;flags=NCRYPT_PAD_PKCS1_FLAG;}
        else if(sigalg==RD_KAFKA_CRYPTO_ES256){
                if(wcscmp(group,NCRYPT_ECDSA_ALGORITHM_GROUP)||NCryptGetProperty(key->key,NCRYPT_LENGTH_PROPERTY,(PBYTE)&bits,sizeof(bits),&got,0)!=ERROR_SUCCESS||bits!=256)goto done;
                if(NCryptGetProperty(key->key,NCRYPT_ALGORITHM_PROPERTY,(PBYTE)name,sizeof(name),&got,0)!=ERROR_SUCCESS)goto done;
                if(wcscmp(name,NCRYPT_ECDSA_P256_ALGORITHM))goto done;
        }else goto done;
        if(digest(RD_KAFKA_CRYPTO_SHA256,data,n,hash))goto done;
        if(NCryptSignHash(key->key,pad,hash,sizeof(hash),NULL,0,&size,flags|NCRYPT_SILENT_FLAG)!=ERROR_SUCCESS)goto done;
        sig=malloc(size);if(!sig||NCryptSignHash(key->key,pad,hash,sizeof(hash),sig,size,&size,flags|NCRYPT_SILENT_FLAG)!=ERROR_SUCCESS)goto done;
        if(sigalg==RD_KAFKA_CRYPTO_ES256&&size!=64)goto done;
        *out=sig;*on=size;sig=NULL;ok=1;
done:SecureZeroMemory(hash,sizeof(hash));free(sig);if(!ok)snprintf(e,en,"BCrypt signing failed or algorithm/key mismatch");return ok?0:-1;
}
static void global_noop(void) {}
const rd_kafka_crypto_ops_t rd_kafka_crypto_bcrypt_ops={"bcrypt",global_noop,global_noop,digest,hmac,pbkdf2,random_bytes,key_load,sign_data,key_destroy};
