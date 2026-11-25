# SSL keys generation for tests

The Makefile in this directory generates a PKCS#12 keystore 
and corresponding PEM certificate and key for testing 
SSL keys and keystore usage in librdkafka.

The `client2_der` target derives the single CA certificate, the DER
certificate and the unencrypted PKCS#8 key (PEM and DER) of client2.
Test 0193 uses them with `rd_kafka_conf_set_ssl_cert()`.

To update those files with a newer OpenSSL version, just run `make`.

# Requirements

* OpenSSL >= 1.1.1
* Java keytool >= Java 11
* GNU Make >= 4.2