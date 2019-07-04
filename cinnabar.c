//========================================================================
// Cinnabar
// Copyright (c) 2016, Pascal Levy
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//========================================================================

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "cinnabar.h"

//========================================================================
// Helper functions.
//========================================================================

//--------------------------------------------------------------
// In debug mode, print an error on the console.
//--------------------------------------------------------------

#ifdef NDEBUG
#define debug(...) ((void) 0);
#else
static void _debug(const char * message, ...) {
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    fputc('\n', stderr);
    va_end(args);
}
#define debug(message, ...) _debug(message, ##__VA_ARGS__)
#endif

//--------------------------------------------------------------
// Erase a memory chunk. We cannot use a regular memset here,
// because it would probably be optimized away by most compilers.
//--------------------------------------------------------------

static void zeromem(void * ptr, size_t length) {
    static void * (* volatile memset_ptr)(void *, int, size_t) = memset;
    (*memset_ptr)(ptr, 0, length);
}

//--------------------------------------------------------------
// Decode a base 64 encoded string. CR and LF characters are
// ignored. Any other non-base64 character triggers an error.
//--------------------------------------------------------------

static uint8_t * base64_decode(const char * data, size_t in_length, size_t * out_length) {

    static uint8_t decode_table[256] = {
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 65, 66, 66, 65, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66, 66, 66, 63, 
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 66, 66, 64, 66, 66, 
        66,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 66, 66, 66, 66, 
        66, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 
    };

    size_t estimated_size = in_length * 3 / 4 + 1;
    uint8_t * output = (uint8_t *) malloc(estimated_size);
    uint8_t * dest = output;

    uint8_t quad[4];
    int count = 0, ending = 0;

    for (size_t i = 0; i < in_length; i++) {
        uint8_t v = decode_table[(uint8_t) data[i]];
        if (v > 65) {
            debug("base64: illegal character %02X in input stream", (int) (unsigned char) data[i]);
            free(output);
            return NULL;
        } else if (v == 64) {
            quad[count++] = v;
            ending = 1;
        } else if (v < 64) {
            quad[count++] = v;
            if (ending) {
                debug("base64: unexpected characters after '='");
                free(output);
                return NULL;
            }
        }

        if (count == 4) {
            *dest++ = (quad[0] << 2) | (quad[1] >> 4);
            if (quad[2] != 64) {
                *dest++ = (quad[1] << 4) | (quad[2] >> 2);
                if (quad[3] != 64) {
                    *dest++ = (quad[2] << 6) | quad[3];
                }
            }
            count = 0;
        }
    }

    if (count != 0) {
        debug("base64: incomplete input stream");
        free(output);
        return NULL;
    }

    *out_length = dest - output;
    return output;
}

//========================================================================
// SHA-256.
//========================================================================

//--------------------------------------------------------------
// Macros and types.
//--------------------------------------------------------------

#define SHR(x, n)		(x >> n)
#define ROTR(x, n)		((x >> n) | (x << (32 - n)))

#define S0(x)			(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x)			(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
#define S2(x)			(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x)			(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define F0(x, y, z)		((x & y) | (z & (x | y)))
#define F1(x, y, z)		(z ^ (x & (y ^ z)))

#define R(t)			( W[t] = S1(W[t - 2]) + W[t - 7] + S0(W[t - 15]) + W[t - 16] )

#define P(a, b, c, d, e, f, g, h, x, K)			\
{												\
    tmp1 = h + S3(e) + F1(e, f, g) + K + x;		\
    tmp2 = S2(a) + F0(a, b, c);					\
    d += tmp1;									\
	h = tmp1 + tmp2;							\
}

#define SHA256_DIGEST_LENGTH   32

typedef struct _CTX_SHA256 {
    uint8_t		buffer[64];
    uint32_t	state[8];
    size_t      count;
}
    CTX_SHA256;

//--------------------------------------------------------------
// Process a chunk of 64 bytes.
//--------------------------------------------------------------

static void sha256_process(CTX_SHA256 * ctx, const uint8_t * data) {
    uint32_t A = ctx->state[0];
    uint32_t B = ctx->state[1];
    uint32_t C = ctx->state[2];
    uint32_t D = ctx->state[3];
    uint32_t E = ctx->state[4];
    uint32_t F = ctx->state[5];
    uint32_t G = ctx->state[6];
    uint32_t H = ctx->state[7];
	uint32_t tmp1, tmp2, W[64];

    for (size_t i = 0; i < 16; i++) {
        W[i] = (((uint32_t) data[0]) << 24) | (((uint32_t) data[1]) << 16) | (((uint32_t) data[2]) << 8) | ((uint32_t) data[3]);
        data += 4;
    }

    P(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98);
    P(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
    P(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF);
    P(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5);
    P(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B);
    P(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1);
    P(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4);
    P(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5);
    P(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98);
    P(H, A, B, C, D, E, F, G, W[ 9], 0x12835B01);
    P(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
    P(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
    P(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
    P(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
    P(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
    P(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
    P(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
    P(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
    P(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
    P(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
    P(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
    P(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
    P(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
    P(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
    P(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
    P(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
    P(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
    P(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
    P(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
    P(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
    P(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
    P(B, C, D, E, F, G, H, A, R(31), 0x14292967);
    P(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
    P(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
    P(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
    P(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
    P(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
    P(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
    P(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
    P(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
    P(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
    P(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
    P(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
    P(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
    P(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
    P(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
    P(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
    P(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
    P(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
    P(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
    P(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
    P(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
    P(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
    P(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
    P(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
    P(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
    P(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
    P(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
    P(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
    P(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
    P(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
    P(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
    P(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
    P(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

//--------------------------------------------------------------
// Process a chunk of data of arbitrary size.
//--------------------------------------------------------------

static void sha256_update(CTX_SHA256 * ctx, const void * data, size_t length) {
	uint8_t * ptr = (uint8_t *) data;
	uint64_t rem = ctx->count & 63;

	if (rem + length >= 64) {
		size_t k = 0;
		if (rem) {
			k = 64 - (size_t) rem;
			memcpy(ctx->buffer + rem, ptr, k);
			sha256_process(ctx, ctx->buffer);
		}
		for ( ; k + 64 <= length; k += 64) {
            sha256_process(ctx, ptr + k);
        }
		memcpy(ctx->buffer, ptr + k, length - k);
	} else {
		memcpy(ctx->buffer + rem, ptr, length);
	}

	ctx->count += length;
}

//--------------------------------------------------------------
// Compute the SHA-256 digest of a data block.
//--------------------------------------------------------------

static void sha256(void * digest, const void * data, size_t length) {
    CTX_SHA256 ctx;
    ctx.count = 0;
	ctx.state[0] = 0x6A09E667;
	ctx.state[1] = 0xBB67AE85;
	ctx.state[2] = 0x3C6EF372;
	ctx.state[3] = 0xA54FF53A;
	ctx.state[4] = 0x510E527F;
	ctx.state[5] = 0x9B05688C;
	ctx.state[6] = 0x1F83D9AB;
	ctx.state[7] = 0x5BE0CD19;
    sha256_update(&ctx, data, length);

	uint8_t	final[80];
	uint64_t bits = ((uint64_t) ctx.count) << 3;
	final[79] = (uint8_t) bits;
	final[78] = (uint8_t) (bits >> 8);
	final[77] = (uint8_t) (bits >> 16);
	final[76] = (uint8_t) (bits >> 24);
	final[75] = (uint8_t) (bits >> 32);
	final[74] = (uint8_t) (bits >> 40);
	final[73] = (uint8_t) (bits >> 48);
	final[72] = (uint8_t) (bits >> 56);
	zeromem(final, 72);

	size_t offset = (ctx.count & 63) + 16;
	if (offset > (55 + 16)) {
        offset -= 64;
    }
	final[offset] = 0x80;
	sha256_update(&ctx, final + offset, 80 - offset);
    zeromem(final, sizeof(final));

    uint8_t * dest = (uint8_t *) digest;
    for (size_t i = 0; i < 8; i++) {
        dest[0] = (uint8_t) (ctx.state[i] >> 24);
        dest[1] = (uint8_t) (ctx.state[i] >> 16);
        dest[2] = (uint8_t) (ctx.state[i] >> 8);
        dest[3] = (uint8_t) ctx.state[i];
        dest += 4;
    }

    zeromem(&ctx, sizeof(ctx));
}

//========================================================================
// Minimal implementation of big integer arithmetics. There is no support
// for negative values and only functions required by RSA signing schemes
// are provided.
//========================================================================

typedef struct _BIGINT {
	size_t		length;         // number of digit used.
    size_t      allocated;      // number of digit actually allocated.
	uint32_t    digits[0];      // digits.
}
	BIGINT;

typedef struct _CTX_BARRETT {
    BIGINT    * factor;         // floor(4^k / modulus)
    BIGINT    * modulus;        // modulus
    size_t      shift_digits;   // k / 32
    size_t      shift_bits;     // k % 32
}
    CTX_BARRETT;

//--------------------------------------------------------------
// Allocate a big integer with the specified number of digits.
//--------------------------------------------------------------

static BIGINT * bigint_alloc(size_t digit_count) {
    BIGINT * r = (BIGINT *) malloc(sizeof(BIGINT) + digit_count * sizeof(uint32_t));
    zeromem(r->digits, digit_count * sizeof(uint32_t));
    r->length = r->allocated = digit_count;
    return r;
}

//--------------------------------------------------------------
// Free a big integer. Before being released, memory is erased
// so no sensitive material is left behind.
//--------------------------------------------------------------

static void bigint_free(BIGINT * b) {
    zeromem(b, sizeof(BIGINT) + b->allocated * sizeof(uint32_t));
    free(b);
}

//--------------------------------------------------------------
// Clamp useless null digits on the left.
//--------------------------------------------------------------

static void bigint_clamp(BIGINT * a) {
	size_t k = a->allocated;
	while (k > 0 && !a->digits[k - 1]) {
        k--;
    }
	a->length = k;
}

//--------------------------------------------------------------
// Compute log256 of an integer = number of bytes required to
// convert this integer to a base 256 representation.
//--------------------------------------------------------------

static size_t bigint_log256(BIGINT * a) {
    size_t size = 0;
    if (a->length > 0) {
        size = (a->length - 1) * sizeof(uint32_t);
        uint32_t k = a->digits[a->length - 1];
        while (k) {
            size++;
            k >>= 8;
        }
    }
    return size;
}

//--------------------------------------------------------------
// PKCS Octet Stream To Integer. It creates a big integer by
// interpreting a stream of bytes as a base 256 big endian number
// and converting it to our internal representation, i.e.,
// base 2^32 little endian.
//--------------------------------------------------------------

static BIGINT * bigint_os2ip(const uint8_t * data, size_t length) {
    BIGINT * r = bigint_alloc((length + sizeof(uint32_t) - 1) / sizeof(uint32_t));
    const uint8_t * src = data + length - 1;
    for (size_t i = 0; i < r->length; i++) {
        uint32_t v = 0;
        for (size_t j = 0; j < sizeof(uint32_t) && src >= data; j++) {
            v |= ((uint32_t) *src--) << (j * 8);
        }
        r->digits[i] = v;
    }
    bigint_clamp(r);
    return r;
}

//--------------------------------------------------------------
// Integer to PKCS Octet Stream. It converts a big integer to
// a base 256 big endian number.
//--------------------------------------------------------------

static void bigint_i2osp(const BIGINT * a, uint8_t * data, size_t length) {
    uint8_t * dest = data + length - 1;
    for (size_t i = 0; i < a->length; i++) {
        uint32_t v = a->digits[i];
        for (size_t j = 0; j < sizeof(uint32_t) && dest >= data; j++) {
            *dest-- = (uint8_t) v;
            v >>= 8;
        }
    }
    while (dest >= data) {
        *dest-- = 0;
    }
}

//--------------------------------------------------------------
// Compare two big integers and return -1 if a < b, +1 if a > b,
// and 0 if a == b.
//--------------------------------------------------------------

static int bigint_compare(const BIGINT * a, const BIGINT * b) {
	if (a->length > b->length) {
        return 1;
    }
	if (a->length < b->length) {
        return -1;
    }
    if (a->length > 0) {
        size_t n = a->length;
        const uint32_t * pa = a->digits + n;
        const uint32_t * pb = b->digits + n;
        while (n--) {
            pa--, pb--;
            if (*pa > *pb) {
                return 1;
            }
            if (*pa < *pb) {
                return -1;
            }
        }
    }
    return 0;
}

//--------------------------------------------------------------
// Subtract two big integers. Since this implementation of big
// integer arithmetics does not support negative values, this
// function expects a > b.
//--------------------------------------------------------------

static BIGINT * bigint_subtract(const BIGINT * a, const BIGINT * b) {
#ifndef NDEBUG
    if (bigint_compare(a, b) < 0) {
        debug("bigint: subtraction would generate a negative number");
        return NULL;
    }
#endif

    BIGINT * r = bigint_alloc(a->length);
	uint32_t * pr = r->digits;

	const uint32_t * pa = a->digits;
	const uint32_t * pb = b->digits;
	uint64_t carry = 0;

    size_t i = 0;
	for (; i < b->length; i++) {
		uint64_t x = ((uint64_t) *pa++) - ((uint64_t) *pb++) - carry;
		*pr++ = (uint32_t) x;
		carry = x >> ((sizeof(uint64_t) * 8) - 1);
	}
	for (; i < a->length; i++) {
		uint64_t x = ((uint64_t) *pa++) - carry;
		*pr++ = (uint32_t) x;
		carry = x >> ((sizeof(uint64_t) * 8) - 1);
	}

	bigint_clamp(r);
    return r;
}

//--------------------------------------------------------------
// Multiply two big integers.
//--------------------------------------------------------------

static BIGINT * bigint_multiply(const BIGINT * a, const BIGINT * b) {
    BIGINT * r;
	size_t n1 = a->length;
	size_t n2 = b->length;

	if (!n1 || !n2) {
        r = bigint_alloc(0);
	} else {
        r = bigint_alloc(n1 + n2);
        for (size_t i = 0; i < n1; i++) {
            uint64_t t = a->digits[i];
            uint32_t * p = r->digits + i;
            uint64_t carry = 0;
            for (size_t j = 0; j < n2; j++) {
                uint64_t x = (*p) + (t * (uint64_t) b->digits[j]) + carry;
                *p++ = (uint32_t) x;
                carry = x >> (sizeof(uint32_t) * 8);
            }
            if (carry) {
                *p = (uint32_t) carry;
            }
        }
    }

    bigint_clamp(r);
    return r;
}

//--------------------------------------------------------------
// Divide two big integers and return the quotient. The remainder
// is not returned.
//--------------------------------------------------------------

static BIGINT * bigint_divide(const BIGINT * num, const BIGINT * div) {
    BIGINT * rem = bigint_alloc(div->length + 1);
    rem->length = 0;

    size_t n = (num->length > div->length) ? num->length - div->length : 0;
    BIGINT * quo = bigint_alloc(n + 1);

    const uint32_t * pn = num->digits + num->length;
    uint32_t * pq = quo->digits + num->length;
    
    for (size_t i = 0; i < num->length; i++) {
        pn--, pq--;
        for (uint32_t m = 1 << ((sizeof(uint32_t) * 8) - 1); m; m >>= 1) {
            uint32_t * pr = rem->digits;
            uint64_t carry = (*pn & m) != 0;
            for (size_t k = 0; k < rem->length; k++) {
                uint64_t x = (((uint64_t) *pr) << 1) | carry;
                *pr++ = (uint32_t) x;
                carry = x >> (sizeof(uint32_t) * 8);
            }
            if (carry) {
                rem->length++;
                *pr = (uint32_t) carry;
            }

            if (bigint_compare(rem, div) >= 0) {
                uint32_t * pr = rem->digits;
                const uint32_t * pd = div->digits;
                uint64_t carry = 0;
                for (size_t k = 0; k < div->length; k++) {
                    uint64_t x = ((uint64_t) *pr) - ((uint64_t) *pd++) - carry;
                    *pr++ = (uint32_t) x;
                    carry = x >> ((sizeof(uint64_t) * 8) - 1);
                }
                if (carry) {
                    (*pr)--;
                }
                while (rem->length > 0 && !rem->digits[rem->length - 1]) {
                    rem->length--;
                }
                *pq |= m;
            }
        }
    }

    bigint_free(rem);
    bigint_clamp(quo);
    return quo;
}

//--------------------------------------------------------------
// Initialize a context to perform Barrett reduction for the
// specified modulus.
//--------------------------------------------------------------

static CTX_BARRETT * bigint_barrett_init(const BIGINT * mod) {
    if (!mod->length) {
        debug("bigint: division by zero");
        return NULL;
    }
    CTX_BARRETT * ctx = (CTX_BARRETT *) malloc(sizeof(CTX_BARRETT));

    ctx->modulus = bigint_alloc(mod->length);
    memcpy(ctx->modulus->digits, mod->digits, mod->length * sizeof(uint32_t));

    size_t k = (mod->length - 1) * 8 * sizeof(uint32_t);
    uint32_t last = mod->digits[mod->length - 1];
    while (last) {
        k++;
        last >>= 1;
    }

    size_t shift = 2 * k;
	ctx->shift_digits = shift / (sizeof(uint32_t) * 8);
	ctx->shift_bits = shift - ctx->shift_digits * (sizeof(uint32_t) * 8);
    
    BIGINT * num = bigint_alloc(ctx->shift_digits + 1);
    num->digits[ctx->shift_digits] = 1 << ctx->shift_bits;
    ctx->factor = bigint_divide(num, mod);
    bigint_free(num);

    return ctx;
}

//--------------------------------------------------------------
// Free a Barrett context.
//--------------------------------------------------------------

static void bigint_barrett_free(CTX_BARRETT * ctx) {
    if (ctx) {
        bigint_free(ctx->factor);
        bigint_free(ctx->modulus);
        zeromem(ctx, sizeof(CTX_BARRETT));
        free(ctx);
    }
}

//--------------------------------------------------------------
// Barrett reduction.
//--------------------------------------------------------------

static BIGINT * bigint_barrett_reduce(const CTX_BARRETT * ctx, const BIGINT * x) {
    BIGINT * mul = bigint_multiply(x, ctx->factor);
    BIGINT * t;

    if (ctx->shift_digits >= mul->length) {
        t = bigint_alloc(x->length);
        memcpy(t->digits, x->digits, x->length * sizeof(uint32_t));
    } else {
        BIGINT * t1 = bigint_alloc(mul->length - ctx->shift_digits);
		uint32_t * px = mul->digits + ctx->shift_digits;
		uint32_t * pt = t1->digits;

		size_t i;
		for (i = ctx->shift_digits; i < mul->length; i++) {
            *pt++ = *px++;
        }
		for ( ; i < t1->length; i++) *pt++ = 0;

    	if (ctx->shift_bits) {
            uint32_t * pt = t1->digits + t1->length - 1;
            uint64_t carry = 0;
            for (size_t i = 0; i < t1->length; i++) {
                uint64_t x = ((uint64_t) *pt) | carry;
                *pt-- = (uint32_t) (x >> ctx->shift_bits);
                carry = x << (sizeof(uint32_t) * 8);
            }
        }

        bigint_clamp(t1);
        BIGINT * t2 = bigint_multiply(t1, ctx->modulus);
        bigint_free(t1);
        t = bigint_subtract(x, t2);
        bigint_free(t2);
    }
    bigint_free(mul);

    if (bigint_compare(ctx->modulus, t) <= 0) {
        BIGINT * t3 = bigint_subtract(t, ctx->modulus);
        bigint_free(t);
        t = t3;
    }

    return t;
}

//--------------------------------------------------------------
// Modular exponentiation.
//--------------------------------------------------------------

static BIGINT * bigint_expmod(const BIGINT * b, const BIGINT * e, const BIGINT * m) {
    CTX_BARRETT * ctx = bigint_barrett_init(m);
    if (!ctx) {
        return NULL;
    }

    BIGINT * base = bigint_barrett_reduce(ctx, b);
    BIGINT * result = bigint_alloc(1);
    result->digits[0] = 1;

    for (size_t i = 0; i < e->length; i++) {
        uint32_t exp = e->digits[i];
        for (size_t j = 0; j < sizeof(uint32_t) * 8; j++) {
            if ((exp & 1) != 0) {
                BIGINT * tmp = bigint_multiply(result, base);
                bigint_free(result);
                result = bigint_barrett_reduce(ctx, tmp);
                bigint_free(tmp);
            }

            BIGINT * tmp = bigint_multiply(base, base);
            bigint_free(base);
            base = bigint_barrett_reduce(ctx, tmp);
            bigint_free(tmp);

            exp >>= 1;
            if (exp == 0 && i == e->length - 1) {
                break;
            }
        }
    }

    bigint_barrett_free(ctx);
    bigint_free(base);
    return result;
}

//========================================================================
// Basic ASN.1 parsing. This implementation is taylored for RSA signing.
// It only supports small SEQUENCEs (less than 10 items), INTEGER, NULL,
// OBJECT ID and BIT STRING data types. Other types, if encountered, are
// ignored. BIT STRINGs are always treated as encapsulated ASN.1 objects.
//========================================================================

//--------------------------------------------------------------
// Constants and types.
//--------------------------------------------------------------

typedef enum {
    Asn1TypeInteger     = 0x02,
    Asn1TypeBitString   = 0x03,
    Asn1TypeNull        = 0x05,
    Asn1TypeObjectId    = 0x06,
    Asn1TypeSequence    = 0x30,
}
    Asn1Type;

typedef struct _ASN1 {
    Asn1Type    type;
    union {
        BIGINT * bigint;
        struct {
            size_t          count;
            struct _ASN1  * items[10];
        }
            sequence;
        struct {
            size_t          length;
            uint32_t        values[8];
        }
            objectid;
        struct {
            struct _ASN1  * encapsulated;
        }
            bitstring;
    }
        u;
}
    ASN1;

//--------------------------------------------------------------
// Free an ASN.1 object. Before being released, memory is erased
// so no sensitive material is left behind.
//--------------------------------------------------------------

static void asn1_free(ASN1 * obj) {
    if (obj) {
        if (obj->type == Asn1TypeInteger) {
            bigint_free(obj->u.bigint);
        } else if (obj->type == Asn1TypeSequence) {
            for (size_t i = 0; i < obj->u.sequence.count; i++) {
                asn1_free(obj->u.sequence.items[i]);
            }
        } else if (obj->type == Asn1TypeBitString) {
            asn1_free(obj->u.bitstring.encapsulated);
        }
        zeromem(obj, sizeof(ASN1));
        free(obj);
    }
}

//--------------------------------------------------------------
// Recursively parse an ASN.1 data block.
//--------------------------------------------------------------

static ASN1 * asn1_recursive_parse(const uint8_t * data, size_t available, size_t * read) {
    if (available < 2) {
        debug("asn.1: ill-structured DER stream.");
        return NULL;
    }

    size_t pos = 0;
    int code = data[pos++] & 0x3F;
    size_t length = data[pos++];

    if (length & 0x80) {
        size_t count = length & 0x7F;
        if (pos + count > available) {
            debug("asn.1: ill-structured DER stream.");
            return NULL;
        }
        length = 0;
        while (count--) {
            length = (length << 8) | data[pos++];
        }
    }

    if (pos + length > available) {
        debug("asn.1: ill-structured DER stream.");
        return NULL;
    }

    ASN1 * obj = (ASN1 *) malloc(sizeof(ASN1));
    zeromem(obj, sizeof(ASN1));
    obj->type = (Asn1Type) code;

    if (code == Asn1TypeInteger) {
        obj->u.bigint = bigint_os2ip(data + pos, length);
        pos += length;
    } else if (code == Asn1TypeObjectId) {
        if (length < 1) {
            debug("asn.1: too short OBJECT IDENTIFIER");
            asn1_free(obj);
            return NULL;
        }
        obj->u.objectid.values[0] = data[pos] / 40;
        obj->u.objectid.values[1] = data[pos] % 40;
        obj->u.objectid.length = 2;
        pos++;
        while (--length) {
            uint8_t v = data[pos++];
            if (obj->u.objectid.length < sizeof(obj->u.objectid.values) / sizeof(obj->u.objectid.values[0])) {
                obj->u.objectid.values[obj->u.objectid.length] = (obj->u.objectid.values[obj->u.objectid.length] << 7) | (v & 0x7F);
                if ((v & 0x80) == 0) {
                    obj->u.objectid.length++;
                }
            }
        }
    } else if (code == Asn1TypeSequence) {
        obj->u.sequence.count = 0;
        size_t maxpos = pos + length;
        while (pos < maxpos) {
            size_t read;
            ASN1 * child = asn1_recursive_parse(data + pos, maxpos - pos, &read);
            if (!child) {
                asn1_free(obj);
                return NULL;
            }

            if (obj->u.sequence.count < (sizeof(obj->u.sequence.items) / sizeof(obj->u.sequence.items[0]))) {
                obj->u.sequence.items[obj->u.sequence.count++] = child;
            } else {
                debug("asn.1: too many objects in SEQUENCE.");
                asn1_free(child);
            }

            pos += read;
        }
    } else if (code == Asn1TypeBitString) {
        if (length < 1 || data[pos] != 0) {
            debug("asn.1: unsupported BIT STRING value");
            asn1_free(obj);
            return NULL;
        }
        size_t read;
        ASN1 * child = asn1_recursive_parse(data + pos + 1, length - 1, &read);
        if (!child || read != length - 1) {
            asn1_free(child);
            return NULL;
        }
        obj->u.bitstring.encapsulated = child;
        pos += length;
    } else {
        if (code != Asn1TypeNull) {
            debug("asn.1: ignoring object of type %02X", code);
        }
        pos += length;
    }

    *read = pos;
    return obj;
}

//--------------------------------------------------------------
// Parse an ASN.1 data block.
//--------------------------------------------------------------

static ASN1 * asn1_parse(const uint8_t * data, size_t length) {
    size_t read;
    ASN1 * obj = asn1_recursive_parse(data, length, &read);
    if (obj) {
        if (read < length) {
            debug("asn.1: extra data in input stream");
            asn1_free(obj);
            obj = NULL;
        }
    }
    return obj;
}

//========================================================================
// Key parsing and validating functions. Keys should be provided in PEM
// format, i.e., base64 encoding of DER encoding of ASN.1 objects. Refer
// to RFC 3447 for more information.
//========================================================================

//--------------------------------------------------------------
// Validate a private key. According to RFC 3447, an RSA private
// key is described by:
//
// Version ::= INTEGER { two-prime(0), multi(1) }
//     (CONSTRAINED BY
//     {-- version must be multi if otherPrimeInfos present --})
//
// RSAPrivateKey ::= SEQUENCE {
//     version           Version,
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER,  -- e
//     privateExponent   INTEGER,  -- d
//     prime1            INTEGER,  -- p
//     prime2            INTEGER,  -- q
//     exponent1         INTEGER,  -- d mod (p-1)
//     exponent2         INTEGER,  -- d mod (q-1)
//     coefficient       INTEGER,  -- (inverse of q) mod p
//     otherPrimeInfos   OtherPrimeInfos OPTIONAL
//  }
//
// This function checks:
//  - the key structure (a SEQUENCE of 9 INTEGERs)
//  - the version number is 0
//  - that n == p * q
//--------------------------------------------------------------

static int validate_private_key(const ASN1 * key) {
    if (!key || key->type != Asn1TypeSequence || key->u.sequence.count != 9) {
        debug("key: invalid private key format");
        return 0;
    }
    for (int i = 0; i < 9; i++) {
        if (key->u.sequence.items[i]->type != Asn1TypeInteger) {
            debug("key: invalid private key format");
            return 0;
        }
    }
    if (key->u.sequence.items[0]->u.bigint->length != 0) {
        debug("key: invalid private key version");
        return 0;
    }

    BIGINT * n1 = bigint_multiply(key->u.sequence.items[4]->u.bigint, key->u.sequence.items[5]->u.bigint);
    BIGINT * n2 = key->u.sequence.items[1]->u.bigint;
    int r = bigint_compare(n1, n2);
    bigint_free(n1);
    if (r != 0) {
        debug("key: inconsistent key: n != p * q");
        return 0;
    }

    return 1;
}

//--------------------------------------------------------------
// Validate a public key. According to RFC 3447, a public key
// key is described by:
//
// PublicKeyInfo ::= SEQUENCE {
//     algorithm       AlgorithmIdentifier,
//     PublicKey       BIT STRING
// }
//
// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm       OBJECT IDENTIFIER,
//     parameters      ANY DEFINED BY algorithm OPTIONAL
// }
//
// RSAPublicKey ::= SEQUENCE {
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER   -- e
// }
//
// This function checks:
//  - the key structure
//  - the algorithm identifier is 1.2.840.113549.1.1.1
//--------------------------------------------------------------

static int validate_public_key(const ASN1 * key) {
    if (!key || key->type != Asn1TypeSequence || key->u.sequence.count != 2 ||
         key->u.sequence.items[0]->type != Asn1TypeSequence || key->u.sequence.items[0]->u.sequence.count != 2) {
        debug("key: invalid public key format");
        return 0;
    }
    
// TODO: to be completed

    return 1;
}

//--------------------------------------------------------------
// Extract a key from PEM data and validate it using the
// specified function.
//--------------------------------------------------------------

static ASN1 * read_key(const char * pem, const char * tag, int (*validate)(const ASN1 *)) {
    char marker[40];
    sprintf(marker, "-----BEGIN %s KEY-----", tag);
    const char * p1 = strstr(pem, marker);
    if (!p1) {
        debug("key: begin mark not found");
        return NULL;
    }
    p1 += strlen(marker);

    sprintf(marker, "-----END %s KEY-----", tag);
    const char * p2 = strstr(p1, marker);
    if (!p2) {
        debug("key: end mark not found");
        return NULL;
    }

    size_t len;
    uint8_t * data = base64_decode(p1, p2 - p1, &len);
    if (!data) {
        return NULL;
    }

    ASN1 * key = asn1_parse(data, len);
    zeromem(data, len);
    free(data);

    if (!(*validate)(key)) {
        asn1_free(key);
        return NULL;
    }

    return key;
}

//========================================================================
// Signature.
//========================================================================

//--------------------------------------------------------------
// Encode a message into a digest of the specified length using
// the EMSA-PKCS1-v1_5 primitive (see RFC 3447).
//--------------------------------------------------------------

static void message_encode(uint8_t * em, size_t key_length, const void * document_data, size_t document_length) {
    memcpy(em, "\x00\x01", 2);
    memset(em + 2, 0xFF, key_length - SHA256_DIGEST_LENGTH - 20 - 2);
    memcpy(em + key_length - SHA256_DIGEST_LENGTH - 20, "\x00\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 20);
    sha256(em + key_length - SHA256_DIGEST_LENGTH, document_data, document_length);
}

//--------------------------------------------------------------
// Compute the signature of a message using RSASSA-PKCS1-v1.5
// (see RFC 3447).
//--------------------------------------------------------------

CnbrStatus CnbrSignature(CNBR_SIGNATURE * signature, const void * document_data, size_t document_length, const char * pem_private_key) {
    if (!signature) {
        return CnbrInvalidParameter;
    }
    zeromem(signature, sizeof(CNBR_SIGNATURE));
    if (!pem_private_key || (!document_data && document_length > 0)) {
        return CnbrInvalidParameter;
    }

    ASN1 * key = read_key(pem_private_key, "RSA PRIVATE", validate_private_key);
    if (!key) {
        return CnbrInvalidPrivateKey;
    }

    size_t modsize = bigint_log256(key->u.sequence.items[1]->u.bigint);
    if (modsize < SHA256_DIGEST_LENGTH + 20 + 2 + 8) {
        asn1_free(key);
        return CnbrKeyIsTooShort;
    }

    uint8_t * em = (uint8_t *) malloc(modsize);
    message_encode(em, modsize, document_data, document_length);
    BIGINT * m = bigint_os2ip(em, modsize);
    BIGINT * s = bigint_expmod(m, key->u.sequence.items[3]->u.bigint, key->u.sequence.items[1]->u.bigint);
    signature->signature_length = modsize;
    signature->signature_data = em;
    bigint_i2osp(s, signature->signature_data, modsize);
    bigint_free(m);
    bigint_free(s);
    asn1_free(key);

    return CnbrSuccess;
}

//--------------------------------------------------------------
// Verify the signature of a message using RSASSA-PKCS1-v1.5
// (see RFC 3447).
//--------------------------------------------------------------

CnbrStatus CnbrVerifySignature(const uint8_t * signature_data, size_t signature_length, const void * document_data, size_t document_length, const char * pem_public_key) {
    if (!signature_data || !pem_public_key || (!document_data && document_length > 0)) {
        return CnbrInvalidParameter;
    }

    ASN1 * key = read_key(pem_public_key, "PUBLIC", validate_public_key);
    if (!key) {
        return CnbrInvalidPublicKey;
    }

    ASN1 * pubkey = key->u.sequence.items[1]->u.bitstring.encapsulated;
    size_t modsize = bigint_log256(pubkey->u.sequence.items[0]->u.bigint);
    if (modsize != signature_length) {
        asn1_free(key);
        return CnbrInvalidSignature;
    }

    uint8_t * em = (uint8_t *) malloc(2 * modsize);
    BIGINT * s = bigint_os2ip(signature_data, modsize);
    BIGINT * m = bigint_expmod(s, pubkey->u.sequence.items[1]->u.bigint, pubkey->u.sequence.items[0]->u.bigint);
    bigint_i2osp(m, em, modsize);
    message_encode(em + modsize, modsize, document_data, document_length);
    bigint_free(m);
    bigint_free(s);
    asn1_free(key);

    uint8_t diff = 0;
    for (size_t i = 0; i < modsize; i++) {
        diff |= em[i] ^ em[i + modsize];
    }

    free(em);
    return (diff) ? CnbrInvalidSignature : CnbrSuccess;
}

//--------------------------------------------------------------
// Erase and free a signature previouly returned by the
// CnbrSignature method.
//--------------------------------------------------------------

CnbrStatus CnbrEraseSignature(CNBR_SIGNATURE * signature) {
    if (!signature) {
        return CnbrInvalidParameter;
    }
    if (signature->signature_data) {
        zeromem(signature->signature_data, signature->signature_length);
        free(signature->signature_data);
    }
    zeromem(signature, sizeof(CNBR_SIGNATURE));
    return CnbrSuccess;
}

//========================================================================
