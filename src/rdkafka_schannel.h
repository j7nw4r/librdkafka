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
int rd_kafka_schannel_add_certs(HCERTSTORE store,
                                const void *data,
                                size_t size,
                                rd_kafka_cert_enc_t encoding,
                                PCCERT_CONTEXT *first,
                                char *errstr,
                                size_t errstr_size);
int rd_kafka_schannel_import_key(const void *data,
                                 size_t size,
                                 rd_kafka_cert_enc_t encoding,
                                 NCRYPT_PROV_HANDLE *provider,
                                 NCRYPT_KEY_HANDLE *key,
                                 char *errstr,
                                 size_t errstr_size);
#endif
#endif
