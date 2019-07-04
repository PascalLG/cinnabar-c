//========================================================================
// Cinnabar - Test Suite
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

#include <math.h>
#include "../cinnabar.c"

static char privatekey[] =  "-----BEGIN RSA PRIVATE KEY-----\n"
                            "MIIEpAIBAAKCAQEAq9Sl9byoS1h4UmemYVUc31Jd9p0CyFZXgLVhhTm8lLq98v51\n"
                            "uOO7JY4ClKp8WmZ/Hv1RDkxlYtqvrF3zJNgWjgJogQHiV4TdjXtr+CC+7QN9qkTI\n"
                            "k9AWdT1ocL/wzAL6lloqDXYWob3Dl8A3ylrH6qAAumh6GMpq6XwbGM+jr4kLGm4P\n"
                            "VOH30WbVwTqUreyRQJatzscx2gWGeCai80SFaNxAjD/9oMGp+pogSEKVlq1o2dyy\n"
                            "IwSSViDtd/sG2/t2tCBFTkY6PgDLOWQRQX/A34oUPjpShbw4KVxAXHDVhB+0f7X+\n"
                            "kLq5+lbDk4RnZPU3kGCexzeSAEb+4SalABeTIwIDAQABAoIBAA6DyAEaDp1Ou9s6\n"
                            "JjPSnL3Al29dk/6YTIvyxmoalnN50tHT7N3RXt2tQUqNnDOGtPZJL6+lhGr1TiGh\n"
                            "TgiuuDkGuw0qu5PpBU4OPvCW04nx4Yugg9D4ou0EYu4jSJPzLHfG5gZ9EyxWe082\n"
                            "TYAqavjGy0jzylyNvLo8YY2W/Jy3M18vcIZkYbncXWOIDEutVnoXratoJpDcp9VX\n"
                            "Zmjbn5ij2HU5nRXdzBoqkLCyOKLpESubKe0oGv7+Do9eTj9fr0U5RDOFQAPoXjPi\n"
                            "zOHi5H2oTqM9M40ZhHcG81Xw2J+xv6svkv0INChCJt/v6njm8y8be6J8VchqOr15\n"
                            "ugNhbgECgYEA3Ct+jlAVHKHyf8x5VecDj4BHT3/3XnjksG306GYW3/JWHx0cALjd\n"
                            "jhQCcADJM3xvAdwaM3nuU1Z8mPaMefR+Vb0jW97jF7AvnsFVvJ7VonGFDaf5t75i\n"
                            "eEc+HawyDYR5JVa1/+zJyfyuAlkECB25JRUrFgKsOgJBzxWnU+d/dHsCgYEAx8tK\n"
                            "he2jDBlYn/MGD/30vtFppTGv62D6syxDrrOO644KhOYqij9vHcCM1ANFKOTksAYR\n"
                            "aBRGs5J11J/pe0EcRECU5GeNJRcMRFGJHarQTEb0LgG6XxySpfZOfRkdjYXUdiVV\n"
                            "59xlC1hfi9w43KadLZOv27qOqSju2CHbdL6J/3kCgYAi/78EfHJ+tLfJ3QVExI5q\n"
                            "V2f+mUcHe4xPB4uxDdmBDBLoq0XyT3DYzxF8IIPbbWJwFz8LA80A7nSsFDVMhbM3\n"
                            "ifN+/TV4ZIeNYwpwC4fGZOlTvGoT7W3V1O1o5iCmyXJAn0IbRtblBwfaU7AyYhc2\n"
                            "b+EDhLVAG2++raCF0/0M1QKBgQCG20U2GSzQ4drcO+F/sd8dXaR9iIhBzHfrsJkO\n"
                            "tsxlWr7m7aURI7gQ0QM9p+dqrvVdivr80ZLXaqh2GGo0c8Jsn1rgwLSYsHHrO03d\n"
                            "5IosskfnNetif5rMwvA/qFA2UnsSNClEE5NwkPoNIVyQMzYsqV8uZUIeFC8DW/cR\n"
                            "WfszoQKBgQCThl++bj+rdlid/Kg4+E3twMnCBvhFxz6R4m3AJRUwRMBFzOnmUv9l\n"
                            "j+CBJEi33tHJ1XPc21eSJu4GTMgYWtTwQ+xxrcY2XxHyCsjRHBb1532Ex2UtQ13e\n"
                            "W5MWrtKGrSdy+yKwDZ/iKDLO7aFpwJ9RbzmJIP02mG2osIUPBq9OHw==\n"
                            "-----END RSA PRIVATE KEY-----\n";


static char publickey[] =   "-----BEGIN PUBLIC KEY-----\n"
                            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq9Sl9byoS1h4UmemYVUc\n"
                            "31Jd9p0CyFZXgLVhhTm8lLq98v51uOO7JY4ClKp8WmZ/Hv1RDkxlYtqvrF3zJNgW\n"
                            "jgJogQHiV4TdjXtr+CC+7QN9qkTIk9AWdT1ocL/wzAL6lloqDXYWob3Dl8A3ylrH\n"
                            "6qAAumh6GMpq6XwbGM+jr4kLGm4PVOH30WbVwTqUreyRQJatzscx2gWGeCai80SF\n"
                            "aNxAjD/9oMGp+pogSEKVlq1o2dyyIwSSViDtd/sG2/t2tCBFTkY6PgDLOWQRQX/A\n"
                            "34oUPjpShbw4KVxAXHDVhB+0f7X+kLq5+lbDk4RnZPU3kGCexzeSAEb+4SalABeT\n"
                            "IwIDAQAB\n"
                            "-----END PUBLIC KEY-----\n";

static char signature[] =   "5b23bfbe96c5a0c28508399cf3d9c38d12d6cc5b06c949ff6e5d59c481a433ca"
                            "521912ad15f021360322cc94b054fa6381792363544823ff114695de5a895a13"
                            "fa9d59e469d53a325ac70fdfea6dbd4b4df0d1652aea50436682f95b07c113d0"
                            "20dc4c3aa39e2fb775bc0b32990cd906c48dcd8235ba7298246da3b2c8f4fc6d"
                            "e7683fd5e74f90fdc2bd073fb2ace9135287f4ebd1917ce365ee05d646fcb0c9"
                            "ef0eb90507b59495a35c66d51aafc91473e517846a171c460081827a63d44c7c"
                            "7849e0bacc87373aedc37d8fb17badcd86f80ef74e21501e73d401ddd97830da"
                            "f0cbbc03b5dec3dc2b565742e0e36684b4570598c15a4f83b7c200bd93edb561";

//--------------------------------------------------------------

static int test_sha256(const char * message, const char * expected) {
	static char	hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    uint8_t digest[32];
    sha256(digest, message, strlen(message));

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (expected[2 * i] != hex[(digest[i] >> 4) & 0x0F] ||
            expected[2 * i + 1] != hex[digest[i] & 0x0F]) {
                printf("failed: sha256(%s)\n", message);
                return 1;
            }
    }

    return 0;
}

//--------------------------------------------------------------

static BIGINT * bigint_fromstring(const char * num, int radix) {
	size_t el = (size_t) (strlen(num) * log(radix) / log(2.0));
    BIGINT * b = bigint_alloc(1 + el / (sizeof(uint32_t) * 8));
    b->length = 1;
    
    for (const char * p = num; *p; p++) {
        int v;

		if		(*p >= '0' && *p <='9')		v = *p - '0';
		else if (*p >= 'A' && *p <= 'Z')	v = *p - 'A' + 10;
		else if (*p >= 'a' && *p <= 'z')	v = *p - 'a' + 10;
		else								v = 255;
        
        if (v < radix) {
			uint32_t * q = b->digits;
			uint64_t carry = v;
			
			for (size_t i = 0; i < b->length; i++) {
				uint64_t mul = ((uint64_t) *q) * (uint64_t) radix + carry;
				*q++ = (uint32_t) mul;
				carry = mul >> (sizeof(uint32_t) * 8);
			}

			if (carry) {
				*q = (uint32_t) carry;
				b->length++;
			}
        } else {
            free(b);
            return NULL;
        }
    }

    bigint_clamp(b);
    return b;
}

//--------------------------------------------------------------

static int test_bigint_muldiv(const char * a, const char * b, const char * r) {
    int err = 0;
    BIGINT * ba = bigint_fromstring(a, 10);
    BIGINT * bb = bigint_fromstring(b, 10);
    BIGINT * br1 = bigint_fromstring(r, 10);
    BIGINT * br2 = bigint_multiply(ba, bb);
    BIGINT * br3 = bigint_multiply(bb, ba);
    if (bigint_compare(br1, br2) != 0) {
        printf("failed: bigint_multiply(%s, %s)\n", a, b);
        err = 1;
    }
    if (bigint_compare(br1, br3) != 0) {
        printf("failed: bigint_multiply(%s, %s)\n", b, a);
        err = 1;
    }

    if (ba->length) {
        BIGINT * bq = bigint_divide(br1, ba);
        if (bigint_compare(bb, bq) != 0) {
            printf("failed: bigint_divide(%s, %s)\n", r, a);
            err = 1;
        }
        bigint_free(bq);
    }
    if (bb->length) {
        BIGINT * bq = bigint_divide(br1, bb);
        if (bigint_compare(ba, bq) != 0) {
            printf("failed: bigint_divide(%s, %s)\n", r, b);
            err = 1;
        }
        bigint_free(bq);
    }

    bigint_free(ba);
    bigint_free(bb);
    bigint_free(br1);
    bigint_free(br2);
    bigint_free(br3);
    return err;
}

//--------------------------------------------------------------

static int test_bigint_subtract(const char * a, const char * b, const char * r) {
    int err = 0;
    BIGINT * ba = bigint_fromstring(a, 10);
    BIGINT * bb = bigint_fromstring(b, 10);
    BIGINT * br1 = bigint_fromstring(r, 10);
    BIGINT * br2 = bigint_subtract(ba, bb);
    if (bigint_compare(br1, br2) != 0) {
        printf("failed: bigint_subtract(%s, %s)\n", a, b);
        err = 1;
    }
    bigint_free(ba);
    bigint_free(bb);
    bigint_free(br1);
    bigint_free(br2);
    return err;
}

//--------------------------------------------------------------

static int test_bigint_expmod(const char * b, const char * e, const char * m, const char * r, int radix) {
    BIGINT * bb = bigint_fromstring(b, radix);
    BIGINT * be = bigint_fromstring(e, radix);
    BIGINT * bm = bigint_fromstring(m, radix);
    BIGINT * br1 = bigint_fromstring(r, radix);
    BIGINT * br2 = bigint_expmod(bb, be, bm);
    if (bigint_compare(br1, br2) != 0) {
        printf("failed: bigint_expmod(%s, %s, %s)\n", b, e, m);
        return 1;
    }
    bigint_free(bb);
    bigint_free(be);
    bigint_free(bm);
    bigint_free(br1);
    bigint_free(br2);
    return 0;
}

//--------------------------------------------------------------

static int test_signature(const char * message, const char * signature) {
    CNBR_SIGNATURE sign;

    CnbrStatus status = CnbrSignature(&sign, message, strlen(message), privatekey);
    if (status != CnbrSuccess) {
        printf("failed: signature returned %d\n", (int) status);
        return 1;
    }
    
    if (strlen(signature) != 2 * sign.signature_length) {
        printf("failed: signature length = %d, expected %d\n", (int) sign.signature_length, (int) strlen(signature) / 2);
        return 1;
    }

    static char hexa[] = "0123456789abcdef";
    for (size_t i = 0; i < sign.signature_length; i++) {
        if (hexa[(sign.signature_data[i] >> 4) & 0x0F] != signature[2 * i] ||
            hexa[sign.signature_data[i] & 0x0F] != signature[2 * i + 1]) {
                printf("failed: wrong signature\n");
                return 1;
        }
    }

    status = CnbrVerifySignature(sign.signature_data, sign.signature_length, message, strlen(message), publickey);
    if (status != CnbrSuccess) {
        printf("failed: check signature returned %d\n", (int) status);
        return 1;
    }

    CnbrEraseSignature(&sign);
    return 0;
}

//--------------------------------------------------------------

int main(int argc, const char * argv[]) {
    int err = 0;

    printf("Testing SHA-256...\n");
	err += test_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    err += test_sha256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	err += test_sha256("abcdefghijklmnopqrstuvwxyz", "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab", "ff44b236434f4d03d1a3b8bce65d3b89750afdc2591f85c9b1d8d77e116ea9e0");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc", "595615dbe4f0f407ae397d08b4c2cb870cb9b0e11937416f950c5160acf9c005");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd", "784f623b787495078e93ff28a25b581df0584055a7e71d8cd90c454716b92f51");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde", "808f0738aa4401bdee842e5a15a7baad5809f976d8eb6f9bd2683cebd2e8d671");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef", "690c197164b3bafc3a2b94834a9607edbec7b32bb77e33c115f7a3e03fbc90a7");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg", "5c23b54f1767aa26ae7678adaab68e4b843a21d0572cf1a45060bbf55a3907b7");
    err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh", "ebd1e8d5a162faa552fff8894f2b77001124b928d526a2d6b74f788658f63f1e");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi", "050c761c092b0b58514e3b980f9eeabcff934921b9da20c89b67a1a5da84a083");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij", "78a08480079addf8f63112aa195cbb6e940e3bf2efcd331920f0fda2a3556ac6");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk", "5ca3e1ef5207490eac01a795e5cc94d59582a5118bf9534665c8668d87aa647c");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", "2fcd5a0d60e4c941381fcc4e00a4bf8be422c3ddfafb93c809e8d1e2bfffae8e");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm", "1b3cd1877ab2f2f19f7be001722554f336cb799df0329de0bb4c118dc6abc06d");
	err += test_sha256("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx", "6c05be2c4268843ae47e68e611277ce62c02153f2f4d2e1e2a1a4b44f766cf74");

    printf("Testing bigint muldiv...\n");
    err += test_bigint_muldiv("123456789012345678901234567890", "0", "0");
    err += test_bigint_muldiv("123456789012345678901234567890", "1", "123456789012345678901234567890");
    err += test_bigint_muldiv("12345678", "98765432", "1219326221002896");
    err += test_bigint_muldiv("37437493849475938409283018479483403294838393547237029397357287311", "1986738470293887364982039893654932415326482143648697000000989664527891", "74378509262144642596026986730087659415413336115268242322548650156767377919672539461448300355948667214566534875289775887989689259891101");

    printf("Testing bigint subtract...\n");
    err += test_bigint_subtract("123456789012345678901234567890", "0", "123456789012345678901234567890");
    err += test_bigint_subtract("123456789012345678901234567890", "1", "123456789012345678901234567889");
    err += test_bigint_subtract("2835938403857932103487932329103948456", "17634735642838021298194", "2835938403857914468752289491082650262");
    err += test_bigint_subtract("283593840385793210348793232910394845616910365629245", "283593840385793210348793232910394845616910365629245", "0");

    printf("Testing bigint expmod...\n");
    err += test_bigint_expmod("4", "13", "497", "445", 10);
    err += test_bigint_expmod("70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc", "40d60f24b61d76783d3bb1dc00b55f96a2a686f59b3750fdb15c40251c370c65cada222673811bc6b305ed7c90ffcb3abdddc8336612ff13b42a75cb7c88fb936291b523d80acce5a0842c724ed85a1393faf3d470bda8083fa84dc5f31499844f0c7c1e93fb1f734a5a29fb31a35c8a0822455f1c850a49e8629714ec6a2657efe75ec1ca6e62f9a3756c9b20b4855bdc9a3ab58c43d8af85b837a7fd15aa1149c119cfe960c05a9d4cea69c9fb6a897145674882bf57241d77c054dc4c94e8349d376296137eb421686159cb878d15d171eda8692834afc871988f203fc822c5dcee7f6c48df663ea3dc755e7dc06aebd41d05f1ca2891e2679783244d068f", "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1", "7e65b998a05f626b028c75dc3fbf98963dce66d0f4c3ae4237cff304d84d8836cb6bad9ac86f9d1b8a28dd70404788b869d2429f1ec0663e51b753f7451c6b4645d99126e457c1dac49551d86a8a974a3131e9b371d5c214cc9ff240c299bd0e62dbc7a9a2dad9fa5404adb00632d36332d5be6106e9e6ec81cac45cd339cc87abbe7f89430800e16e032a66210b25e926eda243d9f09955496ddbc77ef74f17fee41c4435e78b46965b713d72ce8a31af641538add387fedfd88bb22a42eb3bda40f72ecad941dbffdd47b3e77737da741553a45b630d070bcc5205804bf80ee2d51612875dbc4796960052f1687e0074007e6a33ab8b2085c033f9892b6f74", 16);
    err += test_bigint_expmod("3afbdaec9d872f6619ce373cbf5d9e1d48dbc2d5bf8d71e5d234bb5c7ec319cf9ddbf1b1aa1e82159adb589f7c3929f68a1c6ad323688569bd9aeb447d26e0537e07a79aad5632a5e8c0846e1ec15dd18e97ea5bbfdbb7fff34b80b8d81eb98e6aea4ee416e479f951b61411f2c0a22e005ad30a6481cff7019fa10ac04c0f846762389f7f241797e12f865a883fcff4735d50867082ed6af02a3b6a968a6a052ed85af524e37afb15d29969e3becc8f03895366ff6a5c05f544fe5f67a81999786c9aaabb00ac8b6442d807669a0a295225c11ae3902a228d8c9535acb2892083cd677fd72103073ec760c6e1317d3e81455c0e09689516bc21681c514686bc", "5bd8ff0c81b728d6691f931e545ba156be647513a16f403341218453eb5076980f9a38365aaf9d4942d6ef76600bd0752009dc96a0effde65a5b5235261f1bbb4502b91714515f8e4ddde3c2a96bddef9a9df415a7a9a572f3ff3b2dfd23674ba5385a3b06aa7c1a4be9cd69a8b4b8d204e4b0b3adb2b11e7418b328fa476f86d836b989750cdb7cdde5b888db3b747e82d5e878b473607aa8bcce8d80c40bd43149a84f5579c6b4dcb388a6ebb7710805bd1224c962c809ad2583623a3dfd6ddeb7a5d40840c79780a7e7eac4a4e7740a5603c184470118d46ff68ca3587c6e2ed35d1ee6560237c515fbf5bc0047abad25e71962d3885d90bbcf73df0a2c33", "b968e2aaaee6ac4037af9268d0a90ae37b103c4eb302d0ecc23077752f395e6521647a15ab01117808ed7ddd1279090c42f83deb5029b03216e370a21fcdacc6119385d6e7b278862ff7bfc1461fc7d22ccf02a06c9f4eb63785950bad3b2db9279a973e2fc1e2be6c0d8eb124e0ea97e4642bec8ad0cd16f9ba7c3af22f2d1bdbc7e4d7ae1781d63d22c6a285a52d97730ce3746b94dd4fa4fd3dbd0526fcb141b1fdb99603f41425be8298ff8514a83c639f442f03447908f23603196941d666d2e24cb42a0841c0d99bcbd9db2289c5e2d9863670120b1b2f0ffecf4146d21bfffb1a07e00bc2f18e5909f390e9820b977ca7e3a2c67fdf3147c70a4df445", "7237bc0432abdf7e9c87bcf9a7e26b19b245445ce40d5b7440e343542402d504b2d0885e1cff33c753af3c69cfa5965c36225adfd262e5a4ce80141be5f8c5f8aac2379dede905efdab52e6b8f3601d160179846d429abef8a7623c52c72f43299838ebf0513d36606718057d22f648e4ecff4d5950907eda7f4de76557620b73d687525f29d1829d2baf104e24eedec19a25fe57276c176af6fea1cd67ad3f5243dbea52205be786fdacb131412e2b29fe173d0d824315893fc603d755826b5bf29d52e230e82e2afcd2708cf81bf0e4a38741473a0f11a5b578e0a5dfd62c0ad83189fd1fefd2bfb53c8fb67c0747ab0591db02d3b997dafcd35139e8f34d3", 16);
    err += test_bigint_expmod("03fff4f85fe62f42a8873ec273193b29df5e3dd023cd4fd3a365fec4623be736287c900038599b78e76247b3dfdbabf6dd74212818bada5b1cb02b8e2250cec914b68ca3d45cd361c0ac64347aa55fdda755fac0d2a7e360309b756ed32d1d57966c66d7109e914f1b6fd327ccf07b1c118b5c0ee473f8a00990f2a1f32787f261d8cd9892efa3804863c40ead28933c6baa8983c45029d5a5b1681544b2e42964f6db6d4e29989c8193af366ecb3290f164636abc2588f63d4eb180523b0a0e293c631382b865af1a218edb015f67e5dbd3728f4246fd2c6dc5bab60d541cb3283c2633502bb3b6071a1e5b514db18fc2adca155ac241b859b12ee40903c0bc", "12730bd3b350d605ee49c672c414451f26ebdec12b583ffca7143164a6b7839907ae689d4fedd469a6a9ebb663071af304c0d2ade6ecb6de7efcabc2a75d31fb9be54e44c08764fd929236aa7f3a57cb78b8818ee8b298300b534c3ddc083ae740cfff3535b8ef8165dc5420c5ea4ca50e083cfd96096dd616c925f6bee5a4d8857ac345c6023921a3ffcd4266577bda1063a1ac211618050565aef579d842d9e42bc1d89fc4401d437560278286dd34dbc8da58c945a381804782f73d0bc985ca700f28dfdd8723befb6d5cb7c6a583f0552bd37e0d1cf151e5d67b30aced3b44c53fda93b2b7c13f5ce7022c4365eb795792a62a7eb15d1e7b0e94a8e976a1", "9cc61aadbc7866db61cb03f389782e7369bc9314337efd861e334c7460bac0e6dd9c32e899b88c0e820093a6ef56403b78c459a512538a239c75cb08f3197caeb925a12b7e1685a22632a9022bad2f3e6fb17995292046b8d5bd801474b58797a1d712e902f9c02e61f16d8e72d9880d7fafa40cc7b8d48d1720700e3c310cf0b4336e560776e08ca1ee76e5e735c48d5e3e1cd86bb3ed130719ca778cd1bf2ad5b7126f580417ccd0f1c6709ff7eb238ca9679c6f1717ac523689bbde8e5145fa626ff4853e6bc18c3f8bfc1ef616f3dc98ed3d83329049d3181a050341a7319c6bd0b666a40c56714d0041643980f1824c8c805f2b5273cd6fd729ce67a233", "6eb6e140cbc3e3eed591970997da7c55ca67b958320392342ba59c3351a78a48490c69e8d6db22cea59f48669e7b8955c0a6e50457db2cd798179d276c845b90bc2739ebdb9e2fb0cb75ffdade1145b7bd446aa164141c649bbd3bd4cef8b3730436120ac7747fc2bbbeb2991182a11c61105fdbfc4d5e94ede81122932b9898605c3101c4c479b369cf40deab87e60ee0de6e0f6ca964c4b7b9e4e25e981b6e6b985bc231fb29d11b9a169b0a790f9390a76ca4dbe9dfb0fc53314688c0008bdf6027a594de193ef47cc0f4505334910017e9297a194b26384058287f6036c70172ba1e2897044f54bdf148904b2ad406d196dda716d2278e859b8516a86c7e", 16);
    err += test_bigint_expmod("0c4e6cd7e0d36d2235d85c78a51649909b26be7145933bf02cff70bb63cc305d3e5d797238d39bf5d60a1b87b8375a60f538fbfe75cd39b81ddb2ae0e36b3afdb831320fbd6a0fe0beea24c7d1c440b9cc3eec4bf6bac487de98d7e251442efa210e78ee2117bc151081641b68c6ef73b31f9f678fb89fe75890b66198cfca799f4f38dcd9a38be304df90e7880b43adcd0742ebf31b1e0ddb6857155809810091ffeada5fba085c4a897db17ce6a9d1a4bc251cb10e767d1cb2e73a0e4211766eb374ce54d9f6533631e8c0e499713616afb2ceb506254915a3ccdde6f1a008abb5133b902ac5c1e7b3a3b047ba5f21b8fde6dfd3c715064546e307b28cd6bc", "222f494c75e1fc185670da6c0a1a6d503fc3327961cf94bf3580042bb1938785190f9f51bf90ec720f55c3b001f03d1763a2539a9043d2593ae5ced99c399f6a5488f8b49af998feafdf02b554dbbb5b573f0d478295b58e935da31d8508d5dd88f10a5e3a2b98bc04c21c84bae2821402f437bed4c80f459e841bf893cfbadf403849bfc26a28d27a0f49f12c3ad060865643c1ef4e3d25da0ea45fe2ceda4cba7213dc1f91cbaaf0bc4e51c14488f47a4f74d88c5f8172bd83543a0cc15e0b9dca1eae5f6ee9e828d992d3ffedb5b12d47be3f63050f0f1d1d6f279f380ce08bd89256366d258bb56873d96e2740bc506b9ccc27b9cba3b422bcc74af3f341", "c25b9f2a113e6da122df3784f9ae4da81f2b3383d0ac214945a6cd6c9e0521e1da7bb607ed0c759847c6530e3a3c9bb8260f37dfed7c89b7abf0d9197f4e3bbd8ce61c26b994a47092b4424747c7aef64385f3d793bcc14fa3870fdc4aac72d3cce366ebd3004f0df540fd275ce1d6f845a6d345d050c08ae3800b4c1abf02a084c36ddd0e5a3fd2421c596c6e1499394d0e6344d582c9a5c7e2dd4803c953444f24a61b9993bd4f47a599653499f9f98bb61b38cf2694989ac3e02de3cc4cb2856dc8bd855e25d254297a99c06548d116b3a7e233b10873a6214c70dbcb201f732e2b368cb0a93009b2eac103bb18179dd1dbf4fd02dd361e5a66c384d93387", "8b526331ae640aa70317816868b05a0ef4cdd6b293242fbb96d3afe374f1407102fcbfc8c999e6dc6c93e44418dd9d484a698af9ccde81f87e695a0b48b1be61e6d7ef4c7847b7fcddcd7be9a41b6516a23aec0ef9b6e3eb1a439691300119c4950b9187478cbc7a92867e279b940f86881d896ab1ade4db961908341def9d5486bdb9f2bf8fc996391b8f47576a49cca50cc90744fab3b687d72f0400f96143281bcfde9633d3c4367f5872ed8e2e6e5ac546b9cfa92114ad4c901b0fe1777a7f9a008807f38099c0ca4be29cf5182798aa04b74bb042fe5505cd5a9e766da8b6f81ffb7911f2fb8c8326754ba5b55a8932be5c640dab3b06bba69b7ef0bb85", 16);
    err += test_bigint_expmod("7b1fe1148b7776a05ce429fe4f05e4db101deec7fb0bae8d822734ee3032396550e65215b4774b07e37f58321ad4fcab32a730414a851dbe2c68befea6a225ceacf643a1aa0a2e077f052ed3db41f65c12f53ccc43329e59abf3b1560c7fc9de1ae762e0bcebd0f27f078c0f0c624a79067950433274a0bd2e9325bcd1dcf63d13ddebda0e2edd8224d94f240c87d93ceea6c4b6cf604eb5b9d904072a4b8bcd3e5e16b0ca8dc8751ae669365595658b8d3a45280a99680ae2be4e2bbb194134f0a6760a28580fffa667d293c13ce562474c2e2235025de878f8f6ce35456b64fcad7a67332b5318f0255340a1454b571d3f824b41f4c5e3e068740048341fbc", "00b331892f51055f2faecf0788de855fcd0b5aad1f5329d6f72e3178e6a098476371855190211356ddcd03ee90efa7d17acac22b07a13fbc025079737b86a4f6001eb6856566b7e33532ad57892ba0032afa3259b59841f391e322f96c966ebe653e1982ea04ca3f1892531d7d8ed48920dfe2f0c08f208615bbef2e8a5a8a1a96962aee10270d4b00a48f34b82bbbc7b0d9861afd2434439eed5e9b4e3abea77675074b7e5195206d5e1edb19817408e3653ffb021fe107bee13604778976cb2a16e534102006a7e39d3b7a8aeaa1ea52531bb3f06f44bfc50de9fc6c4d17b5e2790b2fd54040ce593d5fe050ea1a5c6af29e0892d1dbe75a52a8854074b201", "9ae1bda92193873d8b43ac607463544bcd3cc847c9b6b54a8f7772b57e810f7a5cb2593a2a65d2be9cd81bc0c2281df19f45ae70e75aeff6cfda6b76bffcc493c50f7df53c24ed04e27b32ffca5f480c5e6514f4b3426feb0d43f72818eccc6ed0e830a020c055cf9edbf32f734ffd397b16820938bea0dd3197a38dbcc448ee4a31dae3a471ccbbeb77edcb28ea746294ddd1f268651be003b28760a6f32e60dde567fe1a726e2f75d5f9807f120d9bde82f1126a81908579048ac32958d3f1dc33b7931e5bf05ad104f9f68ff4b405f927fd28c98d7b55c5dc2d65b45b900f17425b425bf7f951d1a53c598860bddb95c00a6bccf92c5cb04109992fc25ce7", "4c0787990473cca7bbcc5c697743ea94ca8803402011e680e889f488989d3cdd324ef1355df407e56b0ca415b2ee896a508dd93379397fe59e805552671f81248f1aaa1220bc5a2917d1f0d13ffc4f0e67f9cd76d81a2b1048c00e6e44b1de76bc2ca1465d07d0713e0c6f55eb065d55f8958616f8f7085e5b3e66579b37917c8f67dea2f8ed63fa7b51c3d571de1d8185778ed53b11521f2f79323aed476eb6c950e5da3519c46787ae32b37211aba1019162f25e3b09b8a8a0d8fad230c00efba623d030dcb9061f1d3fa8712c12b6319406b36f178a364771a6bde2d90f4692a23eec16e61669ddc6d3f7abf743884b5639d175f32e276029d4b85c5353b4", 16);
    err += test_bigint_expmod("4f858749ad637115b4807c3b53839c6134469bafff7d4b83343af111d9a66e1a9df22077bef30b3e5d2a4fcf29ca319dc87a8fdc4c7aaa7a98168a1cc2240d924b24a776597928863f8ba9691317eb1a3ed233166d9088b0c817655895f4b418650d59fd76d350d8f04459a469f80506df9a7c880cf9294ef06384daa5070d3e016e1655cddf33d5a3f02464253200d669e67c02d122b12f5e0e86d1b165bd84e286c2de381e91dc792b74fd42285e6a238a186312be671682860f5055232d806cdce24c82ae8f3c1dd68936c44ac0b90f2ef01d9b2cbe8c8d870e66f78ce34e7468eb9b01343cac3a202a3425165a5cfbd74ed30da0113f424d1b3d5c9222bc", "0c6cebff6f42d4bbdc2e2d77f324b4af120adb2bdb162e320caebde7aac4328ae22ae006cccb00907a2347535ae1d260c9acb0780ba44bb726615362c82009985da38fe63001c691c8d6ecd9bbf75bad9ca8b59581baee0905d61249bcbec7a9e539132cda5ad3e1f41b90881a6d34cf3b969d23c6b8e0bfd09d956112a94fce9617d392ac98839769f0aa1eb7e8faa339f034539b517c5bc4a963c03fa73e314c032af01a2beda6a784ccd212e67bd0611ea474bd4f4915fbc32ef88addd4723da33d3857be66aa3728250b37a56e746b127fbfb4fa59272a3ecc8ed7be1ec04162bb00b5a4fd2d0ddcdbe5692fc014c1c4dfa6627679bb6d0faa4dfa456401", "9f6c1310001d11601224f8167bb9066760ec6a2f393c67dadb5a8aa5388694b3db66f37450473c1d676e219c46d3286cdb96a9086cdf4a8c08718df0236c8a582b18ef72dd511e730a4270b27587b344c72ed267687777e0ebb507cf0972b072834192d72e4ae32be704713fb27bda22198d5e23e08f1be66883cf049ce30e3c038b522fe6cfbe0e0c901a147419a5af7b8fd65bab31ec1e7117bced3eb59a072b25bf99f1bb09e0931c26b2297aec46526cad53436257fe93aa04d2b9e2717d3b8cd34f97a735a1af0fcf3e92ac485056cb0649f027895ac28e645bcae46562eeff213170020a0d204e47e67794e04b6c922c7ac0138b15074f85f671d1ee8d", "37c44b047e240c3322b79fdba6c732f6a9442d6231611a3ad3b8d68422fc642a4218b3b784fcd62e49ba65d51f79c1d6df92c2742a550b11a41174de742c1890a39db0a362585f8fe363417f9421f2a375f16a05eae938b24dd4211c058706d66c88acb095f69335513b1fadd464cd219fb5bbc19827ee340614dde05dfcb0cd66744ed249b9bb30b68a2611dc64b8a55ec0dbdd2f70d52b20b6b765fd2634bee50be3dd67cae116d2e74518f68c2fe6a8f1f076ff17057c0629bf9e8b642c93c3612e5c9f79af371e5defe1524506437c3e23b0aa198b4a66a0c6617ea9f7aa39ddda0f72888ed5ced5aae4be60afaf68b72837244a9ac2d4f85eb36c25c443", 16);
    err += test_bigint_expmod("35ae44f63e8d1525652ef5b60c6c38f7d7a85cc1adb80c0750b7c901c18944279b40dd75c51a5d2c002bfce70df4ceea80bef3e8093dbff61b1fb13bba48e49cbd276445647524f3dd4698f299688dc6b7db36f906d631fd287dafc2ba1d91545c9651b75b6efbb371bd986f1ea24806d38af28fbe2983fe6d18abb05002b239157d9c17bd7504cbec46f8766ddd2fa8708fbb3e325679a55caed9b823caec265f4627490e536252b252c41111046290c5cb2438b01317260f70ffa6f98cd6229a872486566e62cc5b14b517130852aca8e3c2236dae222f410229878b291679d28579cde3d711d235eb395a6120d31b3ace59431d8bf2201de7fd4a877ed7bc", "07fc5bba84e49acca9ba72590dff1700f994c5c222aa870be611e623f0ae0bc993f0cf14f8697a54d07880aad87fe4b682fd29573a2b4e248917c089a4d143fafc622c935b8e9a9f8dfdb6eed7e5e6771e405ce464ed2e8353fccde42393c856fdd272107a31aab7347ef823fd9ddf7dfd017ea47ca727a66956ddb6db185cbf8c4ef96d21afb6dd94f368bc56efb9ea22d8bc30615587e0f3088c1aefe68d972f1470228e2281825fbef9f32d7400187f089c07f2523db3cf81792237f910a57887acd484f84fff4eff31c76b5937d1691e082a264ff5865c0b6f8dd9e1c69d4fca3deb97bd36d57f3c5c150b59802a84c3efd65dbc614f27daad20f9d860b3", "934472d6bb967882781d34211ce267dadf4415de32bc7e9eb9aad88c9f88437e5d99e777dd997ff78ec28d5b884881a4dab8eff3c44c23ab78d5d22a92fe1fe1acee6895beff6cb95db365bdcfd06f642b0a1b73a9b83ca45f24c3dbd924be6b8300bf890458302e9f2f8762fe95e370afba5747ec92a308208e45d46dde71ca64235f763ff662495007186e0840ddae74d136f6f8a502367801f744e2d7931ffce25dc23d04f5a7324f585c89d7855b33e00a3fe4b61b7152fd77e16453d01256911945d1d4c9fd51b43bc7fbc7ee33ad57cca94d942d1b85811c4843cf67d3c4ea8777ee75722ab2e6f86583453dba9e87ffcdf32e6c3604023feeaf5a9f89", "0e32579a2cba08ceaa6c07bd09591bd819b7b649cc3edcab72734d0ae6eecf9f41a38b6cffcce4c7bb7ce45f32592d50692dd7320785cc6a4e418ac2af4b381490598a72314b0b0186d97bd282092439bb244af3371bebcd9eeac4c5805b70389a84ab81f0d9651c1788e511eb0ae54fcab5c7acc4b1673edc0c1831e5e1443e7f00db6698e3e7f53d353bc98c16efbde0d0615f3044dba7a75c1fd9b5ccb0a9c4381d4b68c4d7194fdd27227598b18563c120eac08b42147317296461327c813740771d217dc49a4df6d300f6d4ef17b91989bf87fd05ed4716f60f3498d73f08e4f2af54548a1e07db2240c26e7da0ebd58402c5075aebafe21605579cd340", 16);
    err += test_bigint_expmod("0dfcaa3bd30c602238bc936160a618f96fb6de645df2b9f1d33471b1a6f4932dc535b169c6044641cde5289c3a434400593d87116e7a5961115855eaddfbc345d2677610cb475dfd435c70fbf36e3287d7d02511758fc3744b6b22b3823205c78ba45213769fe49b670a118df46b7e877359e0ff5ffbfd76e196f018e0ba8cfb2616888aee891113890d78cd91555ca574ee73eafb773a687ca437efe10945c681135cc2d5859ef446e1ffdbde87d8195534301952fe02d0bc101bc7ff8729d1dd7fb601ee2bf4cc410fc91f40131f9abd62d757e4ee132cc8f20dd2cd83c90edf88021402f731ec17a0208e8e71bc940e45a06fa54a1644fca3585d5dfee1bc", "0065d28bbd58447c0e670541443591daff8edb728bddb8b1f376532819579afc52de4fc7608bac2d43f6ce24708fb82bf127ad706b2877e42fc3d0a94a4481e872628e534e4f6c93aea72ef47abf0bcfdabd6b11e678b16a6f6f129a973c3281362e29ac8ffa63e6f627fdcf583e2ebb0ba4ccbe1b956f897a55be4baec272300d0c9e333226f14d55ac5995d4367212bf9e75ff59eaa2152e6a77bdbea3965b8deabc3815115350ae868777aab2cdd71d7f705b471715f6e61e389e270a8be455dbe82f3b0e922a0e4b7b1bdd3226c6f4f405a347effbb5922311e8cd2f44c30f4f9cfc0d96c73c2f47c150b8ed3af0a5d57a22b0cd2e0d3abe70e9bc584c59", "cdbc7d659f98aba9a7ba2e8be0e6f5664ffe1cef25395d21965f9e08fb99574834c6acb8bc6fb3281ef0bb6c2e07211f056c3fc7686ac21d0bf737c0ea17aacd234bae70fa8c7520ffd7e6663677bdac6432e4d2c47fd45bef7c11d75f27d4be0e8c4caeedaa8b6fe58415679ab15e604967c1f92c9f8705fe80c3ded59793b8573dcb221c23446828250edf89006677deac83b64a36f82a123711b2f0a8073e55345375e250d949b8334c1055dfea02dbfdbe83651153ab1d8e309bd14c04ed85f1a406c78e3723993ddb2e790cf8319cce0ab2b433a77bfaac8e153e78467b9ce5a40caf8c685e738a8756f31ed6657644e68523f76e8f1a59cc0327f42621", "429d98e4f9be2f259787cfed7eb8f9cbdb259b1707019e73c07e2baec34f479d60f613dade3e09a4c1cc703e558e07382efe9c14e7a02220b18e7b2e44d4843cfdf276d60210d3db28f7e3f3bc14ad720a706a5608b5b33b4ee6e9f9fcb2b725ea1c51db9ced1b4605a8c0cf29d3e2403699ac2e96206f51a59c85c8e68fe45a8a71e69c14e865cd2bf92deb756eae2410cd4c51c1b7fad52cfc2f280081a0db68b7160a2120bb2858a5dcffe3d88823a60035b9d85bb29eb9e47e012d4044e6b53c32b455623f3a7a89f15d79f19774d43bd8e6bc753acba2864363591776c6a254a77d61745c51e1cb15b7890009f575545fcd5f9938286732e52292d10af3", 16);
    err += test_bigint_expmod("4d95d5189300c1a4e75db7d4c686a624f97319ec7849eb77ce17e3e084401e4a6ea8d6cb42480dc5271167ffdd36d266e0f1971977cbf5f0fb811d5a750b03ca6eed0f781bb3dd02508e2d51ae31bd0a1cd34bd4c9773fbd7109b27bf9e9f9602031a382f60b8c7be0f805f05069229376910293e83700c1db45284d565d718c672ce35f4cce07a71bf185f0d9e897e2c92b060b1fc0f04907deef4ee54756fd24b272b699348eda1a39c07ca2b26ca5e56bb85c6eb76a1166be4cc66b4f3b92fbb7bc0aac4c8002d06e894e79e98d5b18dd8a569b753f37b09ee0b79e5825a488ab890d4b871387a02d69614066e40f88d21399aea3780d75185c7e502a29bc", "0481e55c0af0c2cf25d9edc8128e6f620ab31ef8cfadad0bc46c31fae0d705128d99e8ed4258ecc583ab32a46f9299c51dd0762005ba1373f7e2fdf9d7f2148ca806f3ba4324a1896e7d646728841f07183176eee67fc3abe3e914b856dae21fef57ee51c17c8ce48213d7c149326f1e0851c2d8739dd6a823f5d060a6f0c4d1f9a15b2c1f320f91de6411d2586df7a4b4212a77cfaf0754850640f14204f7aaf4dfecde9560e7c4140edfb2be1e751e6b7198fff4d1d021cbade29f4e19a074398699efbbfa1b4b9874341b77d50548b6b67b27b5fcf591aec5a23c9688e84dc1efe77b8fd04794f9f95fbe8d643cc3d587d56c846a7bb5d305bc9295746351", "98e9a73ffaa11016b424f7b7c7704170246013400683821fb07c2d5fe5651393f4aa38a6b2b3717867cf8a46d626d41f21678dbf1766f797500e8f01ffdb7db386a6b7b248b17c54b9cf219f29ef32c2a6e9996fb3d8cc34dce6c0346b96bc26456073123d4eb2e7b931bce0144838127a49152a22a0127610d2d5a265a6df7bc39f4c32553ec7dc85d4344343d27a7edcd03fc430448c7f898fc6aad5aa8eaf38813d866fa7875ac31ff91232854f058ed8e4e86378b0dc0e213484dba45960b2b9462f700447eb828d99dffb5edce8142f43d3944f1664bcbe455ec6261e9544d178f59039a6f1cd7a9e863a291546f889f3a03dde97058ca391cf3cca890f", "6a875b3a0c21eea28c926bb4422cfe2814bcdf42aadf219d3a562f49f9624e722adf8c53e88de67cdbf948119446b1b081e949dd704589b744e52d3d49867b1785cc118bca50e9696dabb492eecc31af0d40143d67addf20b7975318a4537a842243323af12a2c139cc3007355dd1514ffad2e6f9e6d82bc552e645b5306b075722342677cc22453f665841a08f916311e884d6a53e7791d636be3ef5b7d88bfd59b792cc558047b1f4e6febf484a40ed0da68425cce96bc110ad3def6712954d92d8cd0cbc98201cf6d7b4de47e5fbdd7a68cce37e6ee1fbf598283550219d3330688b765c483017b6a8fabdd2ad7fc60cc6abf12effb07368022843de02076", 16);
    err += test_bigint_expmod("20f14fe5d3c81e2849a758ab757a0631a6c8f1f5eb90721f9901c0192867f11c2f872eb530f411030214b65bf3240b52a7872e024e658fa66694b57219905f7e811cee23dac8e27c10e1182048e4ebd06ddace6e4c4e023d1fdfaa2651d675a6652aa108b062116483a51cd710ae1e8781cd75c500f28cef69a9d99b256168487a6b9648c129a1adf88b6c00a889b0ac0cafca159dfe59c86bc705a10bbe7cb9da644d7beb5ff85e38d7e575a9027fddb0bd049eeb905e49d2519e11f086151c31497fb328a55bfdcaff43890a7a7c8e0e8e61dfb5b3f761273429484b142227e139ae57c7d6b7f9f8cb3b3d392b4262dd0c679dbf43e7d61bb42d830c78a6bc", "2d120a4e3a2534fbd0a1cd2e00fd68b3376c36e8b1203ac44653372ee205e58258fec118283d0b24be89d40bf339213803357ed2cdaaca8b0ded18a7511050ff10c27d1ae96ef98c1671a7df7a8ed8254b57c34b9264ed2c630f9b17325c016668ca6e317896b8377ee5bb0a1ffbea19b1b654288db7b569913ea8c6c62144ec7f9c710bae4e64cc9cab6022367b2292733784ead2bcc5af3d9c312d4f36c39bf7bc97c6047d86cb8c00921bb046d76d2089bca351a28ac7213edeaa79b3d7454ab0fc280c7162df9a010848e3d2d069c3a710aea7a89ad6c268dcd36de7cd15063ad93ccfb73d85e2a4163ad26099224ff981c2b2db07cd3e3152283a93b4c1", "b233a6f3852556ca64dcaaf7a7a6040280ffbc1ebc2ca20538be2cfdc57e2e91a240ea1f1c3e4b2255fcff5322539b98fdee3951af8b1e91e9489329513d726147f0f47a14dd1e4b99c0ea0844fae41a08101a5e702e53a6f363b445ccf194304062b4973e9385ce7c9c0cd11282c50cd2e119efeb9e09a44125f87843c56398bf6152403e71cb10e30131f59513cdfc3a488aba00365d73c94e4f552b98e5b67be0be78ee3e8519341a887e7a6e848ac2dc58c77ed58234d4afc08ef4e782a0ef23a9f68feba2422c79f7ff62df0bcc6dcc4aa2efb988cf789608df26f7834a4414756c6cd42d04784117b4dfd589207a80348b1677d7c7a528c0bbaf11f23f", "1959992867064adf296177c30d982deb2c21f4ac4da19b1c0ece7ff8d3a062b140ffbf3d4d01463f001d9b012b999072e1f916c17ae9d8a5aab02c086aec3b333256e26cc8a770a66f44e5cc77be217caf22a70faf21827f1a953d1c0cfce59be7a8b7b972c14e7b838831440600770d1c3407ff8e3fe535e384fd171a8eeb7ad9512b4209a7177dcf305de4e7ddf67990775a8136fefbdba3457016e1ceb449c2fca76131b972b45ddd98e7ea04f2814c165d1efb0060790c59e619cdb27dda767ebbc12ea092bc74d5e2735a89eb93629aa2728c5a3226306a718ec156e2dfe2eace62f4a2339b5118772352a4b53a3b8205ffd8e41718a0247dc25cdf43c3", 16);
    err += test_bigint_expmod("5667007e5b4f3128e0d0d5c00783f5fc73c1de40bba350db7465bb8d173536340b57006951e7405de9315f76dfddb1fded9aecff704a20364a834925adccbee7f3789526487da4f670363e681bcfae60a3a8a0e9aca136d90ce462e94ff593d7d1d5dc4dac35013e8f48587cdfbde718576661624ddd514ebb0f971829f9a456935cdb5e8b7ed7ab5c275a5b876171cc00f65d3734bcef9f839129dcbd4654b9ecf0d4e0c2807e09ab2b0a2907ddb05a66841f4e06e98055dc8af51304e364cb09c42a5c7f756e9047d3c0434fe1df25c51af95ab2cb6421be2455a654b009c0971f2b7b543a606db9a1f05e5aa26d84ace565a22e2877d638413e8a82f7f5bc", "3b64ebc10344e8ba36d6bda33e0536652911f40ceeeb986e622a30aff3e41b4c267e7885c485de8e89758c90e49304072f884f9d3af4b55cfed4c351b015988d1b85946e049ad1bdec040bf68653cc22f81acbcf929c2c60f2b1d1dcd444f76914ed7fcd105e2cb950452ad93e921d81bd21fbb6e428b591a8b1ec062b46a2d58dd78d2de3321707bb7a617db509de10a6037c30951d361462a9dc24ebff2a936ac12248564f2ac4438ae62da1ddd71a8ffd1e1957c25188bf238c437ec6f165c337f2b19c4edb0b78862fd1de51a673f9778d31ecd7aab593d914dfbbe26656cdc1fd06d82d81e661bd7af39222a624b90c2bde3bc6928e06137af569a48c51", "bf066f288105ddf1588b75137b300f34c56e8eba99c14055f6fca196e756d6cefd07c3a64301e91d6f8cb2069f601a75e99b283beefd1a170b171b077145f27da86b09a7f1f093a6dfacae422fbe805ae904dc63546f1899a945ff1a85c52cd6af167c14c1aa1b4e519dd1f9424343a6a22fed376a242db5a117aa5ed7dee8f4acced8834222b2435e865299493e278140e5951014d82cb6c82403c72895febc3cd208afd368caea0d4634e32e33488b8b7e62fe7461da42f7acb24bce7cb9e1cb5e379ca798a1b683bceeb65ebbc1379d3a551f38f16627d9475780898aea6fd1fb23f85870d886d417524e7fc258d9b2aebd3af5913488143e56aee26b078b", "68fae70e4997ee2bdbbe858dd97c5d2c39ae157d510e95c24dda9fc63a2b056cf0159c4a84f2e0d44a5af026e89c205ac92fefc2724af03c43309a7dee120d252083cbd43f82901b39a14f1c42fa055f1723ff7f6326f257c382acfe6486676b0e94b1c000449448a0a89f4ab5b84504d4130dea6752cb3aa22e8f57c48f3886580de1153bf9761ea0a7c6c88411061b03e97c9b2a376661cea7ccb969e8e25c2d1eac4c98038483c9b8de73d26e033f9aa47587d44db54e2b00224f64e1aed09e5b7eda74568e338b11a18e4be1e1618b8cf0c4c18f7c9f9bf67fc5226f2131fbabf3f026c16f917058a0b9032a66c9da8bf2a5603781f04a36dcfde48b9f13", 16);
    err += test_bigint_expmod("52c6aeed1595f2ae4c14671a3abf51745bab58222e390004d857a3e59ea78a23b9303efe71ccda000af5c915b9a849ef4084613113449fcee42791e66247a6f66270891deb98b55f5a6b72f823d92d28ce08e9f2c5a36a631551d09c48693d0c8affe60f85f349c1edfd392fe32c1fd8f6b12dfd89253ae671b2e59e9b4977513f625a5fff122ecb707e4824e823dc00e8060853162589795c86fb302abe989a03867dfc94ef5ec098554e665096f753c1560b8a083f6a3ab802c9df69bf3f3adb9cd60f4013c846033c29ac8b1a5be3dd997357f9ed7a9cf9f12443bf22bc09f5cfd605d4917f051b41add839651e870268ad1aea8ac8f07775ac57ae98ecbc", "1d3bb87588d7d5a2b5d9730e7d6b892ca4a6023c8fd0f9ef02c84531fa1947aa6ca2b01e1c287935cd8d0591b93d505a586693de02d5a08d4b3fa0bd018c4c9d78b1e0bdae8a6df16408e4949c489acea04a99623e4b9d9b690b30a0774d1a8cc17c6618c72fa9879ebb4f933e7a95bc924a98ad997d8318441744b8eb4bc22ff240d06076580f487d077b9a636795c6ba58794f0b848e0f1ce0e3095d0d267b6ef3dcb05014c0da716c3661993567586991fb9bdd10c29437467217c5df3b169958c031074ef2a35f3634444494221ea75a661f171d1fc68b85e140824769d1be6f0eff195bc08e911577a578834a029c2cc78a89a56fa18e3fdde7a4b277f3", "ac9f9c620fb18a36ad93a206e86471a0cd420637cc5e03114813a6e0c37de6bc57a189cde2305aeee9fab2928edf6ec478d7895c7432f64c8183c9cf211e58ea32b5202dbf29dd5f9ece3fb86c298b562a7e3bd47d626ec3af777c9b6b13272cb6f10246ae69de01c839711e2907e1cf5aa4760ea6a1f60da8d2797e700c4e31ab4a8a4df48008c8c392ae759d3d1f9cf582c1caca86e77540a53a90628bdc4edcc91cbfdddcd6a1d156f28180aed8b6494bc0f622b77a549b404ab1280b4322bedf766b4d1a6caf5a7b088c3b7c1878f4a6007a50bdbad4e5a421247d1f436986a2554601010e758031efd6daeb089f13288ddecbc51816fa69b79e29b3b629", "3d430d46be714a410d7cb36b6ad146eb86ebcc9782a80b84620ea7688debe51181212a344f6601d366c5c3023599b96852369afb3e7cdbdeeead7a5d8073b8749ff6feec90191032739a220d809af484f2652358c0ff21d6bfdb3eff7faad7320d57731ce4a91ca93a376bde7fa4f4a8d9bb05be909eb3507aed997f79458bd63d2e4215130ef67d1f81a62f456957e3dde2cef57751455cc0496dbbe48cdcc9206d76f70455dcccc8ac7aa96a1a391d4ce447e7bc956eee0b09af623fa733e8534e580594eaa09544544961c8cabe666cbadd12d3dcd9d3564b000b9aa7737a35bdd3336c61c903eb7be9a510d43eac47f603ec4a1ef9ee1bf305355050795b", 16);
    err += test_bigint_expmod("64dbfa7a11f38185469ca11c96b065043d488f9f3900357aea6ec1047b6130a9fdb87703028c2b9f1449f001f15cf81f8adbfc5cbe14a56979cc4e0ce8e1ecdd12330540065dca6bda464248ab7554a172ce1ff5c3313e04716589cd056685aee312d4c4187f461d47558c6c6ce4b552dce95d8bef986eebabf69bd5ea4da3396f3c9b80c14522e67602a2b36afdadb935ea920eff4b77a82d7ccc5f0c00ea193cf7ad461bb74bfb472f3d44cef391467bc769a1e6337b67bd3b261e1254fd580374accacf388936789ca02bcec922a7797ac94bc372520400f60d4b8e6c555623b19edfbee4737f38524f45dd43ab03cfb6f04563ed50483287791249e207bc", "08b6e87051808536c8723effcc87dc4e32a83c4271c3f1508b2c544dc0dbfd6e4973437c59646dfb8dc7106a32badb796c878cf39ea3bc14d8ddd9a52edce97e2c51ceab38c43f3ae861c2c0912ec83d5bf01eb2610975637872c3809a29d2dd85b2c71836f96809be496af7d3bac3a433cd1ef6c4efd20a9b90c14e232edd857e7f3342dd1b32da9c2238bb6a11f5ea5947bbeef7b50aa01802fb4f5e03bb2a87e290e1dbe14f3d8ae9a4f73cbc7c7d1420e7a5f9ad51a370db97cb67111adccbaf2278c16a9e96c7aa2de751ccbaa3d554f095bc858ef757ca70b60220f9ff81afa1b629356f92897604353e29f1929c64b4a5295c7910807ef1cdb64ee3e9", "abde7ffa9a4bdc822b6006521650a5a351c5856814d48e67bb593f68c90d322c7136626d002314e0518dff53ace11f87d1da0e92cdf3bab5bb06e558dd6ab9e6b781452edf8696291bdccdb80a6d59c2d848ed78da78369d746c7783f11657ed8dda01003c85f8b15e4ed491a838a6f0c7c95c83e200134aedb15559c9b016878a72fa7b83b68d52fd09c24015e3ef607c49b6d5190c1e7aa1c942249aea7127aee4654b7fb66e4043ebe78448cbbf89d7d7b3dbbe7aaff4a514f2f9effefb4c148be06fe349d1c55671363b9848ec9ced574ebaa1d30fccf53e64eb2214ab9bff9836df0700e6b22c9b0a7607c37cea6522ec04c9dfbd5cf391747180e94dc3", "4f5bb8c8bc6a93b10efd994898f5f93b1d544c6800c56af214ebd12d82acb85b7c7a26a207f748ad64734257c2a17225423beb991fe09c9ffaee94b97104b3c2dfe1b6b169f3b9c0c8ec9417594c2c51f79d77d948eb28a5cd426ba186fe9f518864c45897fcd7366ccee4e553714f0ecedfa89ebd1dac26016cd833265e5b98c06781d45a46373e4d713d12d20016c26a6c868639dbc01b317f63022479b9306d2fdc1ebc27ffe6c88e4490f02f7705e310000d873c6fdae96465eb3ebfe82c0d5eaf790bb1528bc5499acf6aec52f8e97c1a3b38860840ca2857f809adce76ee3f453a1680348a5beba889d908cfe1bce67c1ac19899d86cf7ca14ff5c5a51", 16);
    err += test_bigint_expmod("6e7d1908df8aef33acda95d0ee86803056a452b9293245e4f3f965919b21cd2e3771c321fbb8547f91448ecb8442bbe26097b06634c959213327061a699a3e5ed71031a8b5edc14c86c37da72cd57bc28cadfde420c92feeb8d72a54f929a361af35333c64b074bf6c682849746e769d23b90fcecc58908139d6f7765d86b002d37c31a6c28c092cba70e566d5a4b22ba2e8f7ed76e4d4fb531cea5839811677356d55080b11f854b883331f866a5e1e2f1fd1290b41395d73cd1c82eb145530bffa2252bf7adc238360640e351c64777a171818eb3feab21a826aeacfadfff60ce52749274de3fb5c481d794b14f99088951f988565ab704de57b9e1153aebc", "08ad209738d7680610ba50fa80ade4bcc1e7bb7cc25320e71295b4ed47b781074685042ba8c305cdb3ed24516ec965bae2a01d3a5980831c1d2bce6bb9fd11a7ffc72e56bcaf56e82dbd650dd27381b34c8be1330edfc0b022d2e34a93dc99f4e67512c7d0d85bbcf3c1990ab4fde7f5fd152874ca318a427c7966999b7256e1753d0672b11f4a32456ffeeb131e418cfb078ade851be70fba361c2c3cefe318861a2db3a1a36950a598028d3cf9770753e7b3443565b620907a548bbfb3337bd900089fe179162bb7946e33c1cb93f8ffd562e33541856319369152c376776ec2fdb5a3ba00d40d00ae3700421305f8f7059cb596b8f69fc114c045e0429f41", "a2fd6700bdb5cd6d3244e83c6437c677f36a1ccd1becdd4805a254a7d80a6d00b35cffce126528e6d5cb7a3ebf7c7138eb9fe8e50caf470781636cd03c21ecb4b8136e108faf4064879fee09a660ad7b4c1bd1277becfc9dc7f6aa279034ac81602ce6df0c95d6386abc4dce40216efe1222bf9df6630c47eaf4bab4787019b934215edb708d054572462e4dae059720bcaba60693e624cc1c05cae4d2a7123b99adda76bc2adc95e490f6b011ff4f9bc083946edf7092a8ecbc52c1103b76946b7b72b0f06e3f588ab79d71ef256b39629422c5dfba1e380cc70112118c7e1cac8ad85c1f6b29362f067c84c6bd3be5c98f21fbcfd6852c7608e34a27129e5f", "8b7e146c62062bc84f9557e717d6b1275309023405cb9d0b2f67d4d5377514245a90a67f75bfea1551e2e84a7a398d0d53c6bef92b26f7133f6bb5b483f3c28204d06b846f763cba070c916d559aa300e12ddb0c44fbc5e244521e9d3d8d3d4205ec2ac94596a85f5910b0a9d17e255cf7acf59ff02983de58ea7d9b2f1cf3d1e155878acdc81bfaee6f4371d7c3c9ed3e61eed461ae1887ec2a62d60bd08c8ec04d8d5ae961343f509494c104221beff95e2c9e9f833dfbfa166b96644f293e5764a89361157cc845ab6b8e4b88110be287ad5e33a9f8a7730f72f6e16ee0d0c361a33fe745ee25b3941dde50e105276cfc123b4d448f983e31430fa53facfa", 16);
    err += test_bigint_expmod("7e7d47db2a54c2445e5a5a00243dac1d9f09d15eee612b848ed391a21572a190bd1da02126ec908760685d6b7850f5a3815fb9e23642bec315b83df2bfeddb9bcdce908537571926c690de9cccff89dcd3fb0c253ab554a2f7d1937efdb1acd6da913b028465ba7f4407bf5be0585596111fb5b21d1ca4682fe4820c0dd6a48698ceb8153edf749f5fe9f152014ac9fb7edd3d9b6c1f85087e679b91d4450ce0c38bf2bbb03953f87dcf56c3e0205952288045b6852905de2baadd3ca9addff2b11b64841714cda6cd1ffdae5f9ebb0c82d2706aae3f922e441f1cbf71e366aef874a25eaab089786511c45d5f54df8d09bf072e873b8b0856334477c1c7a4bc", "0d75222a196ed84e028db09b49824f2e9043def91b02085af58d233652fd70b2d03c331c5a4f7b2b1b1eed4ca173016a85b15899eb01458a37f0450f9687d705c933764118a81ed681d3848b3541f0febdbcbc6afd194808c02374e3880f2e58473033a661ff385cc746ef81604f72551c4c47715e9484eb4e6d8ea442d881115f3acf9b210f5092789429eda47e6c85caa37b1a051f49f0c97fa3a3f30aa7c476ff5873dbee38c9aacc73557dd6406e2b691ed640e77604eee951ef967c6c2d913e7e3e092854acc38fe42e42ba1dc2724026a26a2c6769ec6ce287847881f8040e91be6706a995e364088890cffda10014f91397dafc26e492e12cd3ac4af7", "df076349ce47632265f0bb8a2ff18b351494f94c5af6ab4abb6b06bae831b286e80419cd03d74fd359c2555bcff12aa9beee716f6b0dcab05f73f9a5896e3fdede9467be6a91f2a3e4091648afa3b3c8e45b28ab42db982a3823cd0d3c37f55924e5ff7488f4db3280df21d84dfef0eb8d3f647b002796147aaaa64bc5ea9112d0cb179d0983ccbcfb69dfe750980e43c9503b09e3b11774feab0f1beaf3b782cd5fb8acf42e6fc5b90696e4e3cd667e071255553882c6dcbbd904df698a5fa5823dbdd25a7d460fe980af18270fc212552c13f6b6b928572aaf85517b9444d899d803dab3811d41d9d5bff400e15b0e127210a24dcbb65456035f62d3a333dd", "68780ba640953112c66fea490a48557a5775f46130631ac9c43b68a3dcf4f6c6c3c140c748af7d8e43fc578ebcdcf9d1f1ed0ec2a88f7e9570604e0355a4228ccd7bc91b0fcd3adbd5b4a45e95bb759cbd1dbd1c0dc96f2bd9078b9ad68e57b7f2989539532a5cf241bdd8693612fa778cf6bc0d147f78626256dd9f6deaec53592e9feeac2b3af4c4bffc77c424c796f47a83932357c29e8e2ddf63f2288323c4bb06ee2e53e9714d4ef924c1e57d1f822c16b399e9de1bae04e27f42ed80f71bb41317a06c708fd3625b7a51548e4f791961e6eb90565a98b76e854bf3b6c1db8678e4e2087a9f858b822b0ec2e502491a9a869104a0a586807cbbf013632c", 16);

    printf("Testing signature...\n");
    err += test_signature("test", signature);

    return err;
}

//========================================================================
