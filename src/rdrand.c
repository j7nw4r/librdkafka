/*
 * librd - Rapid Development C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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

#include "rd.h"
#include "rdrand.h"
#include "rdtime.h"
#include "tinycthread.h"
#include "rdmurmur2.h"

#include "rdkafka_crypto.h"
#if HAVE_GETENTROPY
/* getentropy() can be present in one of these two */
#include <unistd.h>
#include <sys/random.h>
#endif

/* Initial seed with time+thread id */
unsigned int rd_seed() {
        unsigned int seed = 0, rand_bytes_seed = 0;
        struct timeval tv;

        if (rd_rand_bytes((unsigned char *)&rand_bytes_seed,
                          sizeof(rand_bytes_seed)))
                return rand_bytes_seed;

        rd_gettimeofday(&tv, NULL);
        seed = (unsigned int)(tv.tv_usec);
        seed ^= thrd_current_id();

        /* Apply the murmur2 hash to distribute entropy to
         * the whole seed. */
        seed = (unsigned int)rd_murmur2(&seed, sizeof(seed));
        return seed;
}

static int rd_rand() {
        int rand_num;
#if HAVE_RAND_R
        static RD_TLS unsigned int seed = 0;
        if (unlikely(seed == 0)) {
                seed = rd_seed();
        }
        rand_num = rand_r(&seed);
#else
        rand_num = rand();
#endif
        return rand_num;
}

#ifdef _WIN32
static rd_bool_t rd_rand_bytes_by_rand_s(unsigned char *buf, int num) {
        unsigned int rand, retries = 0;
        while (num > 0) {
                errno_t err;
                int i;
                while ((err = rand_s(&rand)) != 0) {
                        if (++retries == 5)
                                return rd_false;
                        rd_usleep(1000, 0); /* wait for more entropy */
                }
                retries = 0;
                i       = sizeof(int);
                while (i-- > 0 && num > 0) {
                        *buf++ = (unsigned char)(rand & 0xff);
                        rand >>= 8;
                        num--;
                }
        }
        return rd_true;
}
#endif

rd_bool_t rd_rand_bytes(unsigned char *buf, unsigned int num) {
#if WITH_CRYPTO
        /* A selected provider's failure must not silently change the source. */
        return rd_kafka_crypto_random(buf,num)==0;
#else
#if HAVE_GETENTROPY
        while(num) {
                size_t chunk=RD_MIN((size_t)num,(size_t)256);
                if(getentropy(buf,chunk))return rd_false;
                buf+=chunk;num-=(unsigned int)chunk;
        }
        return rd_true;
#endif
#ifdef _WIN32
        if (rd_rand_bytes_by_rand_s(buf, num))
                return rd_true;
#endif
        return rd_false;
#endif
}

int rd_jitter(int low, int high) {
        int rand_num = rd_rand();
        return (low + (rand_num % ((high - low) + 1)));
}

void rd_array_shuffle(void *base, size_t nmemb, size_t entry_size) {
        int i;
        void *tmp = rd_alloca(entry_size);

        /* FIXME: Optimized version for word-sized entries. */

        for (i = (int)nmemb - 1; i > 0; i--) {
                int j = rd_jitter(0, i);
                if (unlikely(i == j))
                        continue;

                memcpy(tmp, (char *)base + (i * entry_size), entry_size);
                memcpy((char *)base + (i * entry_size),
                       (char *)base + (j * entry_size), entry_size);
                memcpy((char *)base + (j * entry_size), tmp, entry_size);
        }
}
