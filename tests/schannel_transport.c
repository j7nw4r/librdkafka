/* Native Windows Schannel transport invariants over a real Python TLS peer.
 * Includes the production adapter to inspect private state without a public API.
 * The library under test is linked statically; no fake Kafka protocol is used. */
#include "rdkafka_int.h"
#include "rdkafka_transport_int.h"
#include <winsock2.h>

static int blocked, short_writes, blocked_writes, reads, writes;
static int fault_send(SOCKET fd, const char *buf, int len, int flags) {
        writes++;
        if (blocked) { blocked_writes++; WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
        if (len > 67) { len = 67; short_writes++; }
        return send(fd, buf, len, flags);
}
static int fault_recv(SOCKET fd, char *buf, int len, int flags) {
        reads++;
        if (len > 113) len = 113;
        return recv(fd, buf, len, flags);
}
#define send fault_send
#define recv fault_recv
#include "../src/rdkafka_schannel.c"
#undef send
#undef recv

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "Schannel invariant line %d: %s; %s\n", __LINE__, #x, error); result = 1; goto done; } } while (0)
static int set(rd_kafka_conf_t *conf, const char *name, const char *value, char *error, size_t size) {
        return rd_kafka_conf_set(conf, name, value, error, size) == RD_KAFKA_CONF_OK;
}
static int handshake(rd_kafka_transport_t *transport, char *error, size_t size) {
        rd_kafka_schannel_session_t *s = transport->rktrans_tls;
        ULONGLONG end = GetTickCount64() + 15000;
        while (GetTickCount64() < end) {
                if (rd_kafka_schannel_flush(transport, error, size) == -1) return -1;
                if (s->output_len) { Sleep(1); continue; }
                if (s->handshake_done) return rd_kafka_schannel_verify(transport, error, size);
                if (s->need_read) {
                        int input = rd_kafka_schannel_input(transport, error, size);
                        if (input == -1) return -1;
                        if (s->eof) { rd_snprintf(error, size, "EOF during real Schannel handshake"); return -1; }
                        if (!input) { Sleep(1); continue; }
                }
                if (rd_kafka_schannel_handshake_step(transport, error, size) == -1) return -1;
        }
        rd_snprintf(error, size, "native Schannel handshake deadline exceeded");
        return -1;
}
int main(int argc, char **argv) {
        WSADATA wsa;
        rd_kafka_t rk;
        rd_kafka_broker_t broker;
        rd_kafka_transport_t transport;
        rd_kafka_conf_t *conf = NULL;
        struct sockaddr_in addr;
        SOCKET fd = INVALID_SOCKET;
        u_long nonblock = 1;
        int small = 1024, result = 0, have_lock = 0, have_context = 0;
        int reject, cancel, before;
        char error[1024] = "";
        rd_buf_t sendbuf;
        rd_slice_t slice;
        unsigned char payload[131071], received[sizeof(payload)];
        size_t total = 0, i;
        ULONGLONG deadline;
        if (argc != 8) {
                fprintf(stderr, "Usage: schannel-transport CA.pem client.pem|- key.pem|- verify-host connect-port accept|reject echo|cancel\n");
                return 2;
        }
        reject = !strcmp(argv[6], "reject"); cancel = !strcmp(argv[7], "cancel");
        memset(&rk, 0, sizeof(rk)); memset(&broker, 0, sizeof(broker)); memset(&transport, 0, sizeof(transport));
        CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        conf = rd_kafka_conf_new();
        CHECK(set(conf, "ssl.ca.location", argv[1], error, sizeof(error)));
        if (argv[2][0] == '@') {
                CHECK(set(conf, "ssl.keystore.location", argv[2] + 1, error, sizeof(error)));
                CHECK(set(conf, "ssl.keystore.password", argv[3], error, sizeof(error)));
        } else if (strcmp(argv[2], "-")) {
                CHECK(set(conf, "ssl.certificate.location", argv[2], error, sizeof(error)));
                CHECK(set(conf, "ssl.key.location", argv[3], error, sizeof(error)));
        }
        rk.rk_conf = *conf;
        if (rd_kafka_schannel_ctx_init(&rk, error, sizeof(error)) == -1) {
                if (reject) { printf("PASS expected Schannel configuration rejection: %s\n", error); goto done; }
                CHECK(0);
        }
        have_context = 1;
        CHECK(mtx_init(&broker.rkb_lock, mtx_plain) == thrd_success); have_lock = 1;
        broker.rkb_rk = &rk;
        rd_snprintf(broker.rkb_nodename, sizeof(broker.rkb_nodename), "%s:%s", argv[4], argv[5]);
        transport.rktrans_rkb = &broker;
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); CHECK(fd != INVALID_SOCKET);
        memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons((u_short)atoi(argv[5]));
        CHECK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&small, sizeof(small)) == 0);
        CHECK(ioctlsocket(fd, FIONBIO, &nonblock) == 0);
        transport.rktrans_s = fd;
        transport.rktrans_wsaevent = WSACreateEvent();
        CHECK(transport.rktrans_wsaevent != WSA_INVALID_EVENT);
        if (rd_kafka_schannel_connect(&broker, &transport, error, sizeof(error)) == -1 ||
            handshake(&transport, error, sizeof(error)) == -1) {
                if (reject) { printf("PASS expected Schannel TLS rejection: %s\n", error); goto done; }
                CHECK(0);
        }
        CHECK(!reject);
        for (i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(i * 31 + i / 97);
        rd_buf_init(&sendbuf, 1, sizeof(payload));
        rd_buf_write(&sendbuf, payload, sizeof(payload)); rd_slice_init_full(&slice, &sendbuf);
        blocked = 1;
        CHECK(rd_kafka_schannel_send(&transport, &slice, error, sizeof(error)) == 0);
        CHECK(rd_slice_offset(&slice) == 0 && rd_kafka_schannel_send_pending(&transport, &slice));
        CHECK(((rd_kafka_schannel_session_t *)transport.rktrans_tls)->pending_n <= RD_SCHANNEL_PLAIN_CHUNK);
        CHECK(rd_kafka_transport_request_has_started(&transport, &slice));
        for (i = 0; i < 3; i++) CHECK(rd_kafka_schannel_send(&transport, &slice, error, sizeof(error)) == 0);
        {
                rd_slice_t wrong = slice;
                rd_slice_read(&wrong, NULL, 1);
                CHECK(rd_kafka_schannel_send(&transport, &wrong, error, sizeof(error)) == -1);
        }
        blocked = 0;
        if (cancel) {
                before = writes;
                rd_kafka_schannel_close(&transport);
                CHECK(writes == before);
                rd_buf_destroy(&sendbuf);
                puts("PASS Schannel cancellation: no write after pending-prefix close");
                goto done;
        }
        deadline = GetTickCount64() + 15000;
        while (((rd_kafka_schannel_session_t *)transport.rktrans_tls)->output_len && GetTickCount64() < deadline) {
                CHECK(rd_kafka_schannel_serve(&transport, POLLOUT, error, sizeof(error)) == 0);
                Sleep(1);
        }
        CHECK(rd_slice_offset(&slice) == 0 && rd_kafka_schannel_send_pending(&transport, &slice));
        deadline = GetTickCount64() + 20000;
        while ((rd_slice_remains(&slice) || total < sizeof(payload)) && GetTickCount64() < deadline) {
                rd_buf_t receive;
                rd_slice_t output;
                size_t count;
                int buffered;
                rd_kafka_schannel_session_t *s = transport.rktrans_tls;
                if (rd_slice_remains(&slice)) CHECK(rd_kafka_schannel_send(&transport, &slice, error, sizeof(error)) >= 0);
                rd_buf_init(&receive, 1, 43); rd_buf_write_ensure(&receive, 43, 43);
                buffered = (s->plaintext_len - s->plaintext_of) >= 43;
                before = reads;
                CHECK(rd_kafka_schannel_recv(&transport, &receive, error, sizeof(error)) >= 0);
                if (buffered) CHECK(reads == before);
                count = rd_buf_len(&receive);
                CHECK(total + count <= sizeof(received));
                rd_slice_init_full(&output, &receive);
                rd_slice_read(&output, received + total, count); total += count;
                rd_buf_destroy(&receive);
                if (!count) Sleep(1);
        }
        CHECK(total == sizeof(payload) && !rd_slice_remains(&slice));
        CHECK(!memcmp(payload, received, sizeof(payload)));
        CHECK(short_writes > 0 && blocked_writes >= 4);
        rd_buf_destroy(&sendbuf);
        printf("PASS Schannel exact echo: %u bytes; short writes=%d EAGAIN=%d; deferred commit and buffered plaintext\n",
               (unsigned)total, short_writes, blocked_writes);
done:
        if (transport.rktrans_tls) rd_kafka_schannel_close(&transport);
        if (transport.rktrans_wsaevent) WSACloseEvent(transport.rktrans_wsaevent);
        if (fd != INVALID_SOCKET) closesocket(fd);
        if (have_lock) mtx_destroy(&broker.rkb_lock);
        if (have_context) rd_kafka_schannel_ctx_term(&rk);
        if (conf) rd_kafka_conf_destroy(conf);
        WSACleanup();
        return result;
}
