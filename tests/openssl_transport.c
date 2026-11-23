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
/* Real nonblocking OpenSSL writes over a socketpair. Include the production
 * adapter to inspect its private pending-write ownership without public ABI. */
#include "../src/rdkafka_ssl.c"
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>

typedef struct fixture_s {
        SSL_CTX *client_ctx, *server_ctx;
        SSL *peer;
        rd_kafka_transport_t transport;
        int fd[2];
} fixture_t;

#define CHECK(x)                                                               \
        do {                                                                   \
                if (!(x)) {                                                    \
                        fprintf(stderr, "OpenSSL transport line %d: %s; %s\n", \
                                __LINE__, #x, error);                          \
                        ERR_print_errors_fp(stderr);                           \
                        goto done;                                             \
                }                                                              \
        } while (0)

static int retryable(SSL *ssl, int result) {
        int error = SSL_get_error(ssl, result);
        return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static void fixture_destroy(fixture_t *f) {
        if (f->transport.rktrans_tls)
                rd_kafka_openssl_ops.close(&f->transport);
        SSL_free(f->peer);
        SSL_CTX_free(f->client_ctx);
        SSL_CTX_free(f->server_ctx);
        if (f->fd[0] >= 0)
                close(f->fd[0]);
        if (f->fd[1] >= 0)
                close(f->fd[1]);
}

static int fixture_init(fixture_t *f, char *error, size_t error_size) {
        EVP_PKEY_CTX *keyctx = NULL;
        EVP_PKEY *key        = NULL;
        X509 *cert           = NULL;
        X509_NAME *name;
        rd_kafka_openssl_session_t *session = NULL;
        int size = 1024, i, ok = 0;
        memset(f, 0, sizeof(*f));
        f->fd[0] = f->fd[1] = -1;
        keyctx              = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        cert                = X509_new();
        if (!keyctx || !cert || EVP_PKEY_keygen_init(keyctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(keyctx, 2048) != 1 ||
            EVP_PKEY_keygen(keyctx, &key) != 1 ||
            X509_set_version(cert, 2) != 1 ||
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
            !X509_gmtime_adj(X509_get_notBefore(cert), -60) ||
            !X509_gmtime_adj(X509_get_notAfter(cert), 3600) ||
            X509_set_pubkey(cert, key) != 1)
                goto done;
        name = X509_get_subject_name(cert);
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       (const unsigned char *)"localhost", -1,
                                       -1, 0) != 1 ||
            X509_set_issuer_name(cert, name) != 1 ||
            X509_sign(cert, key, EVP_sha256()) <= 0)
                goto done;
        f->client_ctx = SSL_CTX_new(SSLv23_method());
        f->server_ctx = SSL_CTX_new(SSLv23_method());
        if (!f->client_ctx || !f->server_ctx)
                goto done;
#ifdef SSL_OP_NO_TLSv1_3
        /* Keep the test focused on an application write, without tickets or
         * post-handshake messages competing for the bounded socket buffer. */
        SSL_CTX_set_options(f->client_ctx, SSL_OP_NO_TLSv1_3);
        SSL_CTX_set_options(f->server_ctx, SSL_OP_NO_TLSv1_3);
#endif
        SSL_CTX_set_mode(f->client_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        if (SSL_CTX_use_certificate(f->server_ctx, cert) != 1 ||
            SSL_CTX_use_PrivateKey(f->server_ctx, key) != 1 ||
            socketpair(AF_UNIX, SOCK_STREAM, 0, f->fd) != 0 ||
            setsockopt(f->fd[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)))
                goto done;
        for (i = 0; i < 2; i++) {
                int flags = fcntl(f->fd[i], F_GETFL, 0);
                if (flags < 0 || fcntl(f->fd[i], F_SETFL, flags | O_NONBLOCK))
                        goto done;
        }
        session                  = rd_calloc(1, sizeof(*session));
        f->transport.rktrans_tls = session;
        session->ssl             = SSL_new(f->client_ctx);
        f->peer                  = SSL_new(f->server_ctx);
        f->transport.rktrans_s   = f->fd[0];
        if (!session->ssl || !f->peer ||
            SSL_set_fd(session->ssl, f->fd[0]) != 1 ||
            SSL_set_fd(f->peer, f->fd[1]) != 1)
                goto done;
        SSL_set_connect_state(session->ssl);
        SSL_set_accept_state(f->peer);
        for (i = 0; i < 10000; i++) {
                int a = SSL_do_handshake(session->ssl);
                int b;
                if (a != 1 && !retryable(session->ssl, a))
                        goto done;
                b = SSL_do_handshake(f->peer);
                if (b != 1 && !retryable(f->peer, b))
                        goto done;
                if (a == 1 && b == 1) {
                        ok = 1;
                        break;
                }
        }
done:
        X509_free(cert);
        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(keyctx);
        if (!ok)
                rd_snprintf(error, error_size, "real TLS fixture setup failed");
        return ok;
}

static int exercise(int cancel) {
        fixture_t f;
        rd_buf_t buffer, other;
        rd_slice_t slice, wrong;
        unsigned char payload[131071], received[sizeof(payload)], extra;
        char error[512] = "";
        size_t i, total = 0;
        int result = 1, buffers = 0;
        CHECK(fixture_init(&f, error, sizeof(error)));
        for (i = 0; i < sizeof(payload); i++)
                payload[i] = (unsigned char)(i * 31 + i / 97);
        rd_buf_init(&buffer, 1, sizeof(payload));
        rd_buf_init(&other, 1, sizeof(payload));
        buffers = 1;
        rd_buf_write(&buffer, payload, sizeof(payload));
        rd_buf_write(&other, payload, sizeof(payload));
        rd_slice_init_full(&slice, &buffer);
        CHECK(rd_kafka_openssl_ops.send(&f.transport, &slice, error,
                                        sizeof(error)) == 0);
        CHECK(rd_slice_offset(&slice) == 0);
        CHECK(rd_kafka_openssl_ops.send_pending != NULL);
        CHECK(rd_kafka_openssl_ops.send_pending(&f.transport, &slice));
        CHECK(rd_kafka_transport_request_has_started(&f.transport, &slice));
        CHECK(rd_kafka_openssl_ops.send(&f.transport, &slice, error,
                                        sizeof(error)) == 0);
        wrong = slice;
        CHECK(rd_slice_read(&wrong, NULL, 1) == 1);
        CHECK(!rd_kafka_openssl_ops.send_pending(&f.transport, &wrong));
        CHECK(rd_kafka_openssl_ops.send(&f.transport, &wrong, error,
                                        sizeof(error)) == -1);
        rd_slice_init_full(&wrong, &other);
        CHECK(!rd_kafka_openssl_ops.send_pending(&f.transport, &wrong));
        CHECK(rd_kafka_openssl_ops.send(&f.transport, &wrong, error,
                                        sizeof(error)) == -1);
        if (cancel) {
                unsigned char raw[16384];
                ssize_t n;
                size_t emitted = 0;
                int available  = -1;
                while ((n = recv(f.fd[1], raw, sizeof(raw), 0)) > 0)
                        emitted += (size_t)n;
                CHECK(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
                CHECK(emitted > 0 && emitted < sizeof(payload));
                rd_kafka_openssl_ops.close(&f.transport);
                CHECK(f.transport.rktrans_tls == NULL);
                CHECK(ioctl(f.fd[1], FIONREAD, &available) == 0);
                CHECK(available == 0);
                puts(
                    "PASS OpenSSL cancellation: pending ciphertext discarded; "
                    "no close-notify or write after cancellation");
        } else {
                for (i = 0; i < 100000 && (rd_slice_remains(&slice) ||
                                           total < sizeof(payload));
                     i++) {
                        int n;
                        if (rd_slice_remains(&slice))
                                CHECK(rd_kafka_openssl_ops.send(
                                          &f.transport, &slice, error,
                                          sizeof(error)) >= 0);
                        n = SSL_read(f.peer, received + total,
                                     (int)(sizeof(received) - total));
                        if (n > 0)
                                total += (size_t)n;
                        else
                                CHECK(retryable(f.peer, n));
                }
                CHECK(total == sizeof(payload) && !rd_slice_remains(&slice));
                CHECK(!memcmp(payload, received, sizeof(payload)));
                CHECK(!rd_kafka_openssl_ops.send_pending(&f.transport, &slice));
                {
                        int n = SSL_read(f.peer, &extra, 1);
                        CHECK(n <= 0 &&
                              SSL_get_error(f.peer, n) == SSL_ERROR_WANT_READ);
                }
                puts(
                    "PASS OpenSSL exact retry: 131071 bytes once; offset-zero "
                    "pending request recognized; mismatched retries rejected");
        }
        result = 0;
done:
        if (buffers) {
                rd_buf_destroy(&buffer);
                rd_buf_destroy(&other);
        }
        fixture_destroy(&f);
        return result;
}

int main(void) {
        signal(SIGPIPE, SIG_IGN);
        rd_kafka_global_init();
        rd_kafka_openssl_ops.global_init();
        if (exercise(0) || exercise(1))
                return 1;
        rd_kafka_openssl_ops.global_term();
        return 0;
}
