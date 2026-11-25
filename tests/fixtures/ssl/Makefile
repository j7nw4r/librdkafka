CLIENT2_KEY_PASSWORD ?= use_strong_password_keystore_client2

ssl_keys: clear_keys
	@./create_keys.sh client client2
	@$(MAKE) --no-print-directory client2_der

# Single-certificate, DER and unencrypted PKCS#8 forms of client2 for the
# rd_kafka_conf_set_ssl_cert() tests. Schannel builds need unencrypted keys.
client2_der:
	@awk '/BEGIN CERT/{n++} n==2' client2.certificate.pem > client2.ca.pem
	@openssl x509 -in client2.ca.pem -outform DER -out client2.ca.der
	@openssl x509 -in client2.certificate.pem -outform DER \
		-out client2.certificate.der
	@openssl pkey -in client2.key -passin pass:$(CLIENT2_KEY_PASSWORD) \
		-out client2.pkcs8.key
	@openssl pkey -in client2.pkcs8.key -outform DER -out client2.pkcs8.der

clear_keys:
	@rm -f *.key *.crt *.jks \
	*.csr *.pem *.p12 *.srl *.der extfile

.PHONY: ssl_keys client2_der clear_keys
