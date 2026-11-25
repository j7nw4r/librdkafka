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


#include "test.h"

/**
 * @brief rd_kafka_conf_set_ssl_cert() validates each input immediately, and a
 *        duplicated configuration keeps its certificate material after the
 *        original is cleared and destroyed. The material must stay usable by
 *        live clients, and DER input must replace PEM input.
 *
 * The key is unencrypted PKCS#8 because Schannel builds refuse key passwords.
 */

#define FIXTURES "./fixtures/ssl/"

static const rd_kafka_cert_type_t cert_types[] = {
    RD_KAFKA_CERT_CA, RD_KAFKA_CERT_PUBLIC_KEY, RD_KAFKA_CERT_PRIVATE_KEY};
static const char *pem_files[] = {FIXTURES "client2.ca.pem",
                                  FIXTURES "client2.certificate.pem",
                                  FIXTURES "client2.pkcs8.key"};
static const char *der_files[] = {FIXTURES "client2.ca.der",
                                  FIXTURES "client2.certificate.der",
                                  FIXTURES "client2.pkcs8.der"};

static void set_cert_from_file(rd_kafka_conf_t *conf,
                               rd_kafka_cert_type_t type,
                               rd_kafka_cert_enc_t enc,
                               const char *path) {
        char *buf = malloc(64 * 1024);
        size_t len;
        char errstr[512];
        rd_kafka_conf_res_t res;

        len = test_read_file(path, buf, 64 * 1024);
        TEST_ASSERT(len > 0, "Failed to read %s", path);

        res = rd_kafka_conf_set_ssl_cert(conf, type, enc, buf, len, errstr,
                                         sizeof(errstr));
        /* The setter must keep its own copy of the material. */
        memset(buf, 0, len);
        free(buf);
        TEST_ASSERT(res == RD_KAFKA_CONF_OK, "%s rejected: %s", path, errstr);
}

static void create_clients(rd_kafka_conf_t *conf) {
        rd_kafka_t *rk[2]  = {NULL, NULL};
        rd_bool_t schannel = test_check_builtin("tls_schannel");
        char errstr[512];
        int i;

        for (i = 0; i < 2; i++) {
                rd_kafka_conf_t *copy = rd_kafka_conf_dup(conf);
                test_conf_set(copy, "security.protocol", "ssl");
                rk[i] = rd_kafka_new(RD_KAFKA_PRODUCER, copy, errstr,
                                     sizeof(errstr));
                if (!rk[i] && schannel && strstr(errstr, "ephemeral")) {
                        /* Windows can refuse an in-memory key only after
                         * the key and certificate matched. */
                        TEST_SAY("Schannel refused the in-memory key: %s\n",
                                 errstr);
                        rd_kafka_conf_destroy(copy);
                        continue;
                }
                TEST_ASSERT(rk[i], "Client %d with retained material: %s", i,
                            errstr);
        }
        for (i = 0; i < 2; i++)
                if (rk[i])
                        rd_kafka_destroy(rk[i]);
}

int main_0193_ssl_cert_setters(int argc, char **argv) {
        rd_kafka_conf_t *conf, *copy;
        char errstr[512];
        int i;

        if (!test_check_builtin("ssl")) {
                TEST_SKIP("Test requires TLS support\n");
                return 0;
        }

        conf = rd_kafka_conf_new();
        for (i = 0; i < (int)RD_ARRAYSIZE(cert_types); i++) {
                set_cert_from_file(conf, cert_types[i], RD_KAFKA_CERT_ENC_PEM,
                                   pem_files[i]);
                TEST_ASSERT(rd_kafka_conf_set_ssl_cert(
                                conf, cert_types[i], RD_KAFKA_CERT_ENC_PEM,
                                "not a certificate", 17, errstr,
                                sizeof(errstr)) == RD_KAFKA_CONF_INVALID,
                            "Invalid input for type %d must fail", i);
        }

        copy = rd_kafka_conf_dup(conf);
        for (i = 0; i < (int)RD_ARRAYSIZE(cert_types); i++)
                TEST_ASSERT(rd_kafka_conf_set_ssl_cert(
                                conf, cert_types[i], RD_KAFKA_CERT_ENC_PEM,
                                NULL, 0, errstr,
                                sizeof(errstr)) == RD_KAFKA_CONF_OK,
                            "Clearing type %d failed: %s", i, errstr);
        rd_kafka_conf_destroy(conf);

        create_clients(copy);

        for (i = 0; i < (int)RD_ARRAYSIZE(cert_types); i++)
                set_cert_from_file(copy, cert_types[i], RD_KAFKA_CERT_ENC_DER,
                                   der_files[i]);
        create_clients(copy);
        rd_kafka_conf_destroy(copy);

        return 0;
}
