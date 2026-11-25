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
/* Private, build-selected broker TLS interface. No public ABI. */
#ifndef _RDKAFKA_TLS_H_
#define _RDKAFKA_TLS_H_

#include "rdkafka_transport.h"

/* An adapter owns its client context and the opaque per-connection session
 * in rktrans_tls. The transport and broker keep the socket, the timeouts and
 * the request accounting. send() advances the slice only by the bytes that
 * the adapter has committed. */
typedef struct rd_kafka_tls_ops_s {
        void (*global_init)(void);
        void (*global_term)(void);
        void (*thread_term)(void);
        int (*ctx_init)(rd_kafka_t *rk, char *errstr, size_t errstr_size);
        void (*ctx_term)(rd_kafka_t *rk);
        int (*connect)(rd_kafka_broker_t *rkb,
                       rd_kafka_transport_t *rktrans,
                       char *errstr,
                       size_t errstr_size);
        int (*handshake)(rd_kafka_transport_t *rktrans);
        ssize_t (*send)(rd_kafka_transport_t *rktrans,
                        rd_slice_t *slice,
                        char *errstr,
                        size_t errstr_size);
        ssize_t (*recv)(rd_kafka_transport_t *rktrans,
                        rd_buf_t *rbuf,
                        char *errstr,
                        size_t errstr_size);
        /* True if the adapter holds part of the request in \p slice while
         * the slice offset has not moved. */
        rd_bool_t (*send_pending)(rd_kafka_transport_t *rktrans,
                                  const rd_slice_t *slice);
        void (*close)(rd_kafka_transport_t *rktrans);

        /* Optional hooks for an adapter that buffers socket data itself.
         * pending(): recv() can return data without a new socket event.
         * interests(): socket events the adapter needs, also with no
         * request queued. serve(): handle those events before the
         * transport reads or writes. */
        rd_bool_t (*pending)(rd_kafka_transport_t *rktrans);
        int (*interests)(rd_kafka_transport_t *rktrans);
        int (*serve)(rd_kafka_transport_t *rktrans,
                     int events,
                     char *errstr,
                     size_t errstr_size);
} rd_kafka_tls_ops_t;

extern const rd_kafka_tls_ops_t rd_kafka_openssl_ops;
extern const rd_kafka_tls_ops_t rd_kafka_schannel_ops;
extern const rd_kafka_tls_ops_t *const rd_kafka_tls_ops;

void rd_kafka_tls_init(void);
void rd_kafka_tls_term(void);
void rd_kafka_tls_thread_term(void);
int rd_kafka_tls_ctx_init(rd_kafka_t *rk, char *errstr, size_t errstr_size);
void rd_kafka_tls_ctx_term(rd_kafka_t *rk);

#endif /* _RDKAFKA_TLS_H_ */
