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


/**
 * @brief Base64 encode binary input \p in, and write base64-encoded string
 *        and it's size to \p out. out->ptr will be NULL in case of some issue
 *        with the conversion or the conversion is not supported.
 *
 * @remark out->ptr must be freed after use.
 */
void rd_base64_encode(const rd_chariov_t *in, rd_chariov_t *out) {

        size_t max_len;

        out->size = 0;
        /* Both input and the encoded return length must fit int. */
        if (in->size > (size_t)(INT_MAX / 4) * 3) {
                out->ptr = NULL;
                return;
        }

        max_len  = (((in->size + 2) / 3) * 4) + 1;
        out->ptr = rd_malloc(max_len);

        out->size = base64_encoding_conversion(
            (unsigned char *)out->ptr, (unsigned char *)in->ptr, (int)in->size);

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

        if (!out.ptr)
                return NULL;

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
        size_t first = 0, last = in->size, i, n, capacity;
        unsigned char *dst;
        out->ptr  = NULL;
        out->size = 0;
        while (first < last &&
               (in->ptr[first] == ' ' || in->ptr[first] == '\t' ||
                in->ptr[first] == '\r' || in->ptr[first] == '\n'))
                first++;
        while (last > first &&
               (in->ptr[last - 1] == ' ' || in->ptr[last - 1] == '\t' ||
                in->ptr[last - 1] == '\r' || in->ptr[last - 1] == '\n'))
                last--;
        n = last - first;
        if (n % 4 || n > INT_MAX)
                return -1;
        capacity = (n / 4) * 3;
        dst      = rd_malloc(capacity + 1);
        for (i = 0; i < n; i += 4) {
                unsigned int value = 0;
                int k, pad = 0;
                for (k = 0; k < 4; k++) {
                        unsigned char c = (unsigned char)in->ptr[first + i + k];
                        int v;
                        if (c >= 'A' && c <= 'Z')
                                v = c - 'A';
                        else if (c >= 'a' && c <= 'z')
                                v = c - 'a' + 26;
                        else if (c >= '0' && c <= '9')
                                v = c - '0' + 52;
                        else if (c == '+')
                                v = 62;
                        else if (c == '/')
                                v = 63;
                        else if (c == '=' && i + 4 == n && k >= 2) {
                                v = 0;
                                pad++;
                        } else
                                goto invalid;
                        if (pad && c != '=')
                                goto invalid;
                        value = (value << 6) | (unsigned)v;
                }
                if (pad > 2 || (pad == 2 && (value & 0xffff)) ||
                    (pad == 1 && (value & 0xff)))
                        goto invalid;
                dst[out->size++] = (unsigned char)(value >> 16);
                if (pad < 2)
                        dst[out->size++] = (unsigned char)(value >> 8);
                if (!pad)
                        dst[out->size++] = (unsigned char)value;
        }
        dst[out->size] = 0;
        out->ptr       = (char *)dst;
        return 0;
invalid:
        rd_free(dst);
        out->size = 0;
        return -1;
}
