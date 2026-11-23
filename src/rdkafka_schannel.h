/* Private Windows certificate import helpers. No public/provider ABI. */
#ifndef _RDKAFKA_SCHANNEL_H_
#define _RDKAFKA_SCHANNEL_H_
#if WITH_SCHANNEL
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>
int rd_kafka_schannel_add_certs(HCERTSTORE store, const void *data, size_t size,
                               rd_kafka_cert_enc_t encoding,
                               PCCERT_CONTEXT *first, char *errstr,
                               size_t errstr_size);
int rd_kafka_schannel_import_key(const void *data, size_t size,
                                rd_kafka_cert_enc_t encoding,
                                NCRYPT_PROV_HANDLE *provider,
                                NCRYPT_KEY_HANDLE *key, char *errstr,
                                size_t errstr_size);
#endif
#endif
