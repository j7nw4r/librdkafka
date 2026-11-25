/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2023 Confluent Inc.
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

#include "rdbase64.h"

/* Builds with OpenSSL TLS or the OpenSSL crypto backend link libcrypto. */
#define RD_BASE64_OPENSSL (WITH_SSL || WITH_CRYPTO_OPENSSL)

#if RD_BASE64_OPENSSL
#include <openssl/evp.h>
#else

#define conv_bin2ascii(a, table) ((table)[(a) & 0x3f])

static const unsigned char data_bin2ascii[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encoding_conversion(unsigned char *out,
                                      const unsigned char *in,
                                      int dlen) {
        int i, ret = 0;
        unsigned long l;

        for (i = dlen; i > 0; i -= 3) {
                if (i >= 3) {
                        l = (((unsigned long)in[0]) << 16L) |
                            (((unsigned long)in[1]) << 8L) | in[2];
                        *(out++) = conv_bin2ascii(l >> 18L, data_bin2ascii);
                        *(out++) = conv_bin2ascii(l >> 12L, data_bin2ascii);
                        *(out++) = conv_bin2ascii(l >> 6L, data_bin2ascii);
                        *(out++) = conv_bin2ascii(l, data_bin2ascii);
                } else {
                        l = ((unsigned long)in[0]) << 16L;
                        if (i == 2)
                                l |= ((unsigned long)in[1] << 8L);

                        *(out++) = conv_bin2ascii(l >> 18L, data_bin2ascii);
                        *(out++) = conv_bin2ascii(l >> 12L, data_bin2ascii);
                        *(out++) =
                            (i == 1) ? '='
                                     : conv_bin2ascii(l >> 6L, data_bin2ascii);
                        *(out++) = '=';
                }
                ret += 4;
                in += 3;
        }

        *out = '\0';
        return ret;
}

#endif

/**
 * @brief Base64 encode binary input \p in, and write base64-encoded string
 *        and it's size to \p out. out->ptr will be NULL in case of some issue
 *        with the conversion or the conversion is not supported.
 *
 * @remark out->ptr must be freed after use.
 */
void rd_base64_encode(const rd_chariov_t *in, rd_chariov_t *out) {

        size_t max_len;

        /* OpenSSL takes an |int| argument so the input cannot exceed that. */
        if (in->size > INT_MAX) {
                out->ptr = NULL;
                return;
        }

        max_len  = (((in->size + 2) / 3) * 4) + 1;
        out->ptr = rd_malloc(max_len);

#if RD_BASE64_OPENSSL
        out->size = EVP_EncodeBlock((unsigned char *)out->ptr,
                                    (unsigned char *)in->ptr, (int)in->size);
#else
        out->size = base64_encoding_conversion(
            (unsigned char *)out->ptr, (unsigned char *)in->ptr, (int)in->size);
#endif

        rd_assert(out->size < max_len);
        out->ptr[out->size] = 0;
}


/**
 * @brief Base64 encode binary input \p in.
 * @returns a newly allocated, base64-encoded string or NULL in case of some
 *          issue with the conversion or the conversion is not supported.
 *
 * @remark Returned string must be freed after use.
 */
char *rd_base64_encode_str(const rd_chariov_t *in) {
        rd_chariov_t out;
        rd_base64_encode(in, &out);
        return out.ptr;
}

/**
 * @brief Base64 encode binary input \p in and return a newly allocated,
 *        base64-encoded string with URL-safe characters.
 * @returns a newly allocated, base64-encoded string or NULL in case of some
 *          issue with the conversion or the conversion is not supported.
 *
 * @remark Returned string must be freed after use.
 */
char *rd_base64_encode_str_urlsafe(const rd_chariov_t *in) {
        rd_chariov_t out;
        char *p;
        rd_base64_encode(in, &out);

        /* Replace + with - and / with _ */
        for (p = out.ptr; *p; p++) {
                if (*p == '+')
                        *p = '-';
                else if (*p == '/')
                        *p = '_';
        }

        /* Remove padding '=' characters */
        int newlen = strlen(out.ptr);
        while (newlen > 0 && out.ptr[newlen - 1] == '=') {
                out.ptr[newlen - 1] = '\0';
                newlen--;
        }

        out.size = newlen;
        return out.ptr;
}

/**
 * @brief Base64 decode input string \p in. Ignores leading and trailing
 *         whitespace.
 * @returns * 0 on successes in which case a newly allocated binary string is
 *            set in \p out (and size).
 *          * -1 on invalid Base64.
 *          * -2 on conversion not supported.
 */
int rd_base64_decode(const rd_chariov_t *in, rd_chariov_t *out) {

#if RD_BASE64_OPENSSL
        size_t ret_len;

        /* OpenSSL takes an |int| argument, so |in->size| must not exceed
         * that. */
        if (in->size % 4 != 0 || in->size > INT_MAX) {
                return -1;
        }

        ret_len  = ((in->size / 4) * 3);
        out->ptr = rd_malloc(ret_len + 1);

        if (EVP_DecodeBlock((unsigned char *)out->ptr, (unsigned char *)in->ptr,
                            (int)in->size) == -1) {
                rd_free(out->ptr);
                out->ptr = NULL;
                return -1;
        }

        /* EVP_DecodeBlock will pad the output with trailing NULs and count
         * them in the return value. */
        if (in->size > 1 && in->ptr[in->size - 1] == '=') {
                if (in->size > 2 && in->ptr[in->size - 2] == '=') {
                        ret_len -= 2;
                } else {
                        ret_len -= 1;
                }
        }

        out->ptr[ret_len] = 0;
        out->size         = ret_len;

        return 0;
#else
        return -2;
#endif
}


#include "rdunittest.h"

/**
 * @brief RFC 4648 section 10 vectors through the encoder and, if this build
 *        supports it, the decoder.
 */
int unittest_base64(void) {
        static const char *plain[]   = {"",     "f",     "fo",    "foo",
                                        "foob", "fooba", "foobar"};
        static const char *encoded[] = {
            "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
        static const char *bad[]             = {"A", "Zg=", "Zm9v!AAA"};
        static const unsigned char urlsafe[] = {0xfb, 0xff};
        rd_chariov_t in, out, decoded;
        char *str;
        size_t i;
        int r;

        for (i = 0; i < RD_ARRAYSIZE(plain); i++) {
                in.ptr  = (char *)plain[i];
                in.size = strlen(plain[i]);
                rd_base64_encode(&in, &out);
                RD_UT_ASSERT(out.ptr && out.size == strlen(encoded[i]) &&
                                 !strcmp(out.ptr, encoded[i]),
                             "encode \"%s\"", plain[i]);

                r = rd_base64_decode(&out, &decoded);
                rd_free(out.ptr);
                if (r == -2)
                        continue; /* This build has no decoder. */
                RD_UT_ASSERT(!r && decoded.size == in.size &&
                                 !memcmp(decoded.ptr, in.ptr, in.size),
                             "decode \"%s\"", encoded[i]);
                rd_free(decoded.ptr);
        }

        for (i = 0; i < RD_ARRAYSIZE(bad); i++) {
                in.ptr  = (char *)bad[i];
                in.size = strlen(bad[i]);
                r       = rd_base64_decode(&in, &out);
                RD_UT_ASSERT(r == -1 || r == -2, "decode \"%s\" must fail",
                             bad[i]);
        }

        in.ptr  = (char *)urlsafe;
        in.size = sizeof(urlsafe);
        str     = rd_base64_encode_str_urlsafe(&in);
        RD_UT_ASSERT(str && !strcmp(str, "-_8"), "URL-safe encoding");
        rd_free(str);

        RD_UT_PASS();
}
