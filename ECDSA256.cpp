
#include "pch.h"

#include "ECDSA256.h"


/************************************************************************************************************/
/*																											*/
/* Note: This File is Aggregation of Several Source Files, Seperated by Long Assignment-Comment Lines       */
/*																											*/
/************************************************************************************************************/

/*======================================================================================================================================*/
/*======================================================================================================================================*/


/*
 * Copyright (c) 2016 & 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


 /* see inner.h */
static void br_ccopy(uint32_t ctl, void* dst, const void* src, size_t len)
{
	unsigned char* d;
	const unsigned char* s;

	d = (unsigned char*)dst;
	s = (unsigned char*)src;
	while (len-- > 0) {
		uint32_t x, y;

		x = *s++;
		y = *d;
		*d = MUX(ctl, x, y);
		d++;
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_range_dec32be(uint32_t* v, size_t num, const void* src)
{
	const unsigned char* buf;

	buf = (unsigned char*)src;
	while (num-- > 0) {
		*v++ = br_dec32be(buf);
		buf += 4;
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/



 /*
  * If BR_NO_ARITH_SHIFT is undefined, or defined to 0, then we _assume_
  * that right-shifting a signed negative integer copies the sign bit
  * (arithmetic right-shift). This is "implementation-defined behaviour",
  * i.e. it is not undefined, but it may differ between compilers. Each
  * compiler is supposed to document its behaviour in that respect. GCC
  * explicitly defines that an arithmetic right shift is used. We expect
  * all other compilers to do the same, because underlying CPU offer an
  * arithmetic right shift opcode that could not be used otherwise.
  */
#if BR_NO_ARITH_SHIFT
#define ARSH(x, n)    (((uint32_t)(x) >> (n)) | ((-((uint32_t)(x) >> 31)) << (32 - (n))))
#define ARSHW(x, n)   (((uint64_t)(x) >> (n)) | ((-((uint64_t)(x) >> 63)) << (64 - (n))))
#else
#define ARSH(x, n)    ((*(int32_t *)&(x)) >> (n))
#define ARSHW(x, n)   ((*(int64_t *)&(x)) >> (n))
#endif

  /*
   * Convert an integer from unsigned big-endian encoding to a sequence of
   * 30-bit words in little-endian order. The final "partial" word is
   * returned.
   */
static uint32_t be8_to_le30(uint32_t* dst, const unsigned char* src, size_t len)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len-- > 0) {
		uint32_t b;

		b = src[len];
		if (acc_len < 22) {
			acc |= b << acc_len;
			acc_len += 8;
		}
		else {
			*dst++ = (acc | (b << acc_len)) & 0x3FFFFFFF;
			acc = b >> (30 - acc_len);
			acc_len -= 22;
		}
	}
	return acc;
}

/*
 * Convert an integer (30-bit words, little-endian) to unsigned
 * big-endian encoding. The total encoding length is provided; all
 * the destination bytes will be filled.
 */
static void le30_to_be8(unsigned char* dst, size_t len, const uint32_t* src)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len-- > 0) {
		if (acc_len < 8) {
			uint32_t w;

			w = *src++;
			dst[len] = (unsigned char)(acc | (w << acc_len));
			acc = w >> (8 - acc_len);
			acc_len += 22;
		}
		else {
			dst[len] = (unsigned char)acc;
			acc >>= 8;
			acc_len -= 8;
		}
	}
}

/*
 * Multiply two integers. Source integers are represented as arrays of
 * nine 30-bit words, for values up to 2^270-1. Result is encoded over
 * 18 words of 30 bits each.
 */
static void mul9(uint32_t* d, const uint32_t* a, const uint32_t* b)
{
	/*
	 * Maximum intermediate result is no more than
	 * 10376293531797946367, which fits in 64 bits. Reason:
	 *
	 *   10376293531797946367 = 9 * (2^30-1)^2 + 9663676406
	 *   10376293531797946367 < 9663676407 * 2^30
	 *
	 * Thus, adding together 9 products of 30-bit integers, with
	 * a carry of at most 9663676406, yields an integer that fits
	 * on 64 bits and generates a carry of at most 9663676406.
	 */
	uint64_t t[17];
	uint64_t cc;
	int i;

	t[0] = MUL31(a[0], b[0]);
	t[1] = MUL31(a[0], b[1])
		+ MUL31(a[1], b[0]);
	t[2] = MUL31(a[0], b[2])
		+ MUL31(a[1], b[1])
		+ MUL31(a[2], b[0]);
	t[3] = MUL31(a[0], b[3])
		+ MUL31(a[1], b[2])
		+ MUL31(a[2], b[1])
		+ MUL31(a[3], b[0]);
	t[4] = MUL31(a[0], b[4])
		+ MUL31(a[1], b[3])
		+ MUL31(a[2], b[2])
		+ MUL31(a[3], b[1])
		+ MUL31(a[4], b[0]);
	t[5] = MUL31(a[0], b[5])
		+ MUL31(a[1], b[4])
		+ MUL31(a[2], b[3])
		+ MUL31(a[3], b[2])
		+ MUL31(a[4], b[1])
		+ MUL31(a[5], b[0]);
	t[6] = MUL31(a[0], b[6])
		+ MUL31(a[1], b[5])
		+ MUL31(a[2], b[4])
		+ MUL31(a[3], b[3])
		+ MUL31(a[4], b[2])
		+ MUL31(a[5], b[1])
		+ MUL31(a[6], b[0]);
	t[7] = MUL31(a[0], b[7])
		+ MUL31(a[1], b[6])
		+ MUL31(a[2], b[5])
		+ MUL31(a[3], b[4])
		+ MUL31(a[4], b[3])
		+ MUL31(a[5], b[2])
		+ MUL31(a[6], b[1])
		+ MUL31(a[7], b[0]);
	t[8] = MUL31(a[0], b[8])
		+ MUL31(a[1], b[7])
		+ MUL31(a[2], b[6])
		+ MUL31(a[3], b[5])
		+ MUL31(a[4], b[4])
		+ MUL31(a[5], b[3])
		+ MUL31(a[6], b[2])
		+ MUL31(a[7], b[1])
		+ MUL31(a[8], b[0]);
	t[9] = MUL31(a[1], b[8])
		+ MUL31(a[2], b[7])
		+ MUL31(a[3], b[6])
		+ MUL31(a[4], b[5])
		+ MUL31(a[5], b[4])
		+ MUL31(a[6], b[3])
		+ MUL31(a[7], b[2])
		+ MUL31(a[8], b[1]);
	t[10] = MUL31(a[2], b[8])
		+ MUL31(a[3], b[7])
		+ MUL31(a[4], b[6])
		+ MUL31(a[5], b[5])
		+ MUL31(a[6], b[4])
		+ MUL31(a[7], b[3])
		+ MUL31(a[8], b[2]);
	t[11] = MUL31(a[3], b[8])
		+ MUL31(a[4], b[7])
		+ MUL31(a[5], b[6])
		+ MUL31(a[6], b[5])
		+ MUL31(a[7], b[4])
		+ MUL31(a[8], b[3]);
	t[12] = MUL31(a[4], b[8])
		+ MUL31(a[5], b[7])
		+ MUL31(a[6], b[6])
		+ MUL31(a[7], b[5])
		+ MUL31(a[8], b[4]);
	t[13] = MUL31(a[5], b[8])
		+ MUL31(a[6], b[7])
		+ MUL31(a[7], b[6])
		+ MUL31(a[8], b[5]);
	t[14] = MUL31(a[6], b[8])
		+ MUL31(a[7], b[7])
		+ MUL31(a[8], b[6]);
	t[15] = MUL31(a[7], b[8])
		+ MUL31(a[8], b[7]);
	t[16] = MUL31(a[8], b[8]);

	/*
	 * Propagate carries.
	 */
	cc = 0;
	for (i = 0; i < 17; i++) {
		uint64_t w;

		w = t[i] + cc;
		d[i] = (uint32_t)w & 0x3FFFFFFF;
		cc = w >> 30;
	}
	d[17] = (uint32_t)cc;
}

/*
 * Square a 270-bit integer, represented as an array of nine 30-bit words.
 * Result uses 18 words of 30 bits each.
 */
static void square9(uint32_t* d, const uint32_t* a)
{
	uint64_t t[17];
	uint64_t cc;
	int i;

	t[0] = MUL31(a[0], a[0]);
	t[1] = ((MUL31(a[0], a[1])) << 1);
	t[2] = MUL31(a[1], a[1])
		+ ((MUL31(a[0], a[2])) << 1);
	t[3] = ((MUL31(a[0], a[3])
		+ MUL31(a[1], a[2])) << 1);
	t[4] = MUL31(a[2], a[2])
		+ ((MUL31(a[0], a[4])
			+ MUL31(a[1], a[3])) << 1);
	t[5] = ((MUL31(a[0], a[5])
		+ MUL31(a[1], a[4])
		+ MUL31(a[2], a[3])) << 1);
	t[6] = MUL31(a[3], a[3])
		+ ((MUL31(a[0], a[6])
			+ MUL31(a[1], a[5])
			+ MUL31(a[2], a[4])) << 1);
	t[7] = ((MUL31(a[0], a[7])
		+ MUL31(a[1], a[6])
		+ MUL31(a[2], a[5])
		+ MUL31(a[3], a[4])) << 1);
	t[8] = MUL31(a[4], a[4])
		+ ((MUL31(a[0], a[8])
			+ MUL31(a[1], a[7])
			+ MUL31(a[2], a[6])
			+ MUL31(a[3], a[5])) << 1);
	t[9] = ((MUL31(a[1], a[8])
		+ MUL31(a[2], a[7])
		+ MUL31(a[3], a[6])
		+ MUL31(a[4], a[5])) << 1);
	t[10] = MUL31(a[5], a[5])
		+ ((MUL31(a[2], a[8])
			+ MUL31(a[3], a[7])
			+ MUL31(a[4], a[6])) << 1);
	t[11] = ((MUL31(a[3], a[8])
		+ MUL31(a[4], a[7])
		+ MUL31(a[5], a[6])) << 1);
	t[12] = MUL31(a[6], a[6])
		+ ((MUL31(a[4], a[8])
			+ MUL31(a[5], a[7])) << 1);
	t[13] = ((MUL31(a[5], a[8])
		+ MUL31(a[6], a[7])) << 1);
	t[14] = MUL31(a[7], a[7])
		+ ((MUL31(a[6], a[8])) << 1);
	t[15] = ((MUL31(a[7], a[8])) << 1);
	t[16] = MUL31(a[8], a[8]);

	/*
	 * Propagate carries.
	 */
	cc = 0;
	for (i = 0; i < 17; i++) {
		uint64_t w;

		w = t[i] + cc;
		d[i] = (uint32_t)w & 0x3FFFFFFF;
		cc = w >> 30;
	}
	d[17] = (uint32_t)cc;
}

/*
 * Base field modulus for P-256.
 */
static const uint32_t F256[] = {

	0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x0000003F, 0x00000000,
	0x00000000, 0x00001000, 0x3FFFC000, 0x0000FFFF
};

/*
 * The 'b' curve equation coefficient for P-256.
 */
static const uint32_t P256_B[] = {

	0x27D2604B, 0x2F38F0F8, 0x053B0F63, 0x0741AC33, 0x1886BC65,
	0x2EF555DA, 0x293E7B3E, 0x0D762A8E, 0x00005AC6
};

/*
 * Addition in the field. Source operands shall fit on 257 bits; output
 * will be lower than twice the modulus.
 */
static void add_f256(uint32_t* d, const uint32_t* a, const uint32_t* b)
{
	uint32_t w, cc;
	int i;

	cc = 0;
	for (i = 0; i < 9; i++) {
		w = a[i] + b[i] + cc;
		d[i] = w & 0x3FFFFFFF;
		cc = w >> 30;
	}
	w >>= 16;
	d[8] &= 0xFFFF;
	d[3] -= w << 6;
	d[6] -= w << 12;
	d[7] += w << 14;
	cc = w;
	for (i = 0; i < 9; i++) {
		w = d[i] + cc;
		d[i] = w & 0x3FFFFFFF;
		cc = ARSH(w, 30);
	}
}

/*
 * Subtraction in the field. Source operands shall be smaller than twice
 * the modulus; the result will fulfil the same property.
 */
static void sub_f256(uint32_t* d, const uint32_t* a, const uint32_t* b)
{
	uint32_t w, cc;
	int i;

	/*
	 * We really compute a - b + 2*p to make sure that the result is
	 * positive.
	 */
	w = a[0] - b[0] - 0x00002;
	d[0] = w & 0x3FFFFFFF;
	w = a[1] - b[1] + ARSH(w, 30);
	d[1] = w & 0x3FFFFFFF;
	w = a[2] - b[2] + ARSH(w, 30);
	d[2] = w & 0x3FFFFFFF;
	w = a[3] - b[3] + ARSH(w, 30) + 0x00080;
	d[3] = w & 0x3FFFFFFF;
	w = a[4] - b[4] + ARSH(w, 30);
	d[4] = w & 0x3FFFFFFF;
	w = a[5] - b[5] + ARSH(w, 30);
	d[5] = w & 0x3FFFFFFF;
	w = a[6] - b[6] + ARSH(w, 30) + 0x02000;
	d[6] = w & 0x3FFFFFFF;
	w = a[7] - b[7] + ARSH(w, 30) - 0x08000;
	d[7] = w & 0x3FFFFFFF;
	w = a[8] - b[8] + ARSH(w, 30) + 0x20000;
	d[8] = w & 0xFFFF;
	w >>= 16;
	d[8] &= 0xFFFF;
	d[3] -= w << 6;
	d[6] -= w << 12;
	d[7] += w << 14;
	cc = w;
	for (i = 0; i < 9; i++) {
		w = d[i] + cc;
		d[i] = w & 0x3FFFFFFF;
		cc = ARSH(w, 30);
	}
}

/*
 * Compute a multiplication in F256. Source operands shall be less than
 * twice the modulus.
 */
static void mul_f256(uint32_t* d, const uint32_t* a, const uint32_t* b)
{
	uint32_t t[18];
	uint64_t s[18];
	uint64_t cc, x;
	uint32_t z, c;
	int i;

	mul9(t, a, b);

	/*
	 * Modular reduction: each high word in added/subtracted where
	 * necessary.
	 *
	 * The modulus is:
	 *    p = 2^256 - 2^224 + 2^192 + 2^96 - 1
	 * Therefore:
	 *    2^256 = 2^224 - 2^192 - 2^96 + 1 mod p
	 *
	 * For a word x at bit offset n (n >= 256), we have:
	 *    x*2^n = x*2^(n-32) - x*2^(n-64)
	 *            - x*2^(n - 160) + x*2^(n-256) mod p
	 *
	 * Thus, we can nullify the high word if we reinject it at some
	 * proper emplacements.
	 *
	 * We use 64-bit intermediate words to allow for carries to
	 * accumulate easily, before performing the final propagation.
	 */
	for (i = 0; i < 18; i++) {
		s[i] = t[i];
	}

	for (i = 17; i >= 9; i--) {
		uint64_t y;

		y = s[i];
		s[i - 1] += ARSHW(y, 2);
		s[i - 2] += (y << 28) & 0x3FFFFFFF;
		s[i - 2] -= ARSHW(y, 4);
		s[i - 3] -= (y << 26) & 0x3FFFFFFF;
		s[i - 5] -= ARSHW(y, 10);
		s[i - 6] -= (y << 20) & 0x3FFFFFFF;
		s[i - 8] += ARSHW(y, 16);
		s[i - 9] += (y << 14) & 0x3FFFFFFF;
	}

	/*
	 * Carry propagation must be signed. Moreover, we may have overdone
	 * it a bit, and obtain a negative result.
	 *
	 * The loop above ran 9 times; each time, each word was augmented
	 * by at most one extra word (in absolute value). Thus, the top
	 * word must in fine fit in 39 bits, so the carry below will fit
	 * on 9 bits.
	 */
	cc = 0;
	for (i = 0; i < 9; i++) {
		x = s[i] + cc;
		d[i] = (uint32_t)x & 0x3FFFFFFF;
		cc = ARSHW(x, 30);
	}

	/*
	 * All nine words fit on 30 bits, but there may be an extra
	 * carry for a few bits (at most 9), and that carry may be
	 * negative. Moreover, we want the result to fit on 257 bits.
	 * The two lines below ensure that the word in d[] has length
	 * 256 bits, and the (signed) carry (beyond 2^256) is in cc. The
	 * significant length of cc is less than 24 bits, so we will be
	 * able to switch to 32-bit operations.
	 */
	cc = ARSHW(x, 16);
	d[8] &= 0xFFFF;

	/*
	 * One extra round of reduction, for cc*2^256, which means
	 * adding cc*(2^224-2^192-2^96+1) to a 256-bit (nonnegative)
	 * value. If cc is negative, then it may happen (rarely, but
	 * not neglectibly so) that the result would be negative. In
	 * order to avoid that, if cc is negative, then we add the
	 * modulus once. Note that if cc is negative, then propagating
	 * that carry must yield a value lower than the modulus, so
	 * adding the modulus once will keep the final result under
	 * twice the modulus.
	 */
	z = (uint32_t)cc;
	d[3] -= z << 6;
	d[6] -= (z << 12) & 0x3FFFFFFF;
	d[7] -= ARSH(z, 18);
	d[7] += (z << 14) & 0x3FFFFFFF;
	d[8] += ARSH(z, 16);
	c = z >> 31;
	d[0] -= c;
	d[3] += c << 6;
	d[6] += c << 12;
	d[7] -= c << 14;
	d[8] += c << 16;
	for (i = 0; i < 9; i++) {
		uint32_t w;

		w = d[i] + z;
		d[i] = w & 0x3FFFFFFF;
		z = ARSH(w, 30);
	}
}

/*
 * Compute a square in F256. Source operand shall be less than
 * twice the modulus.
 */
static void square_f256(uint32_t* d, const uint32_t* a)
{
	uint32_t t[18];
	uint64_t s[18];
	uint64_t cc, x;
	uint32_t z, c;
	int i;

	square9(t, a);

	/*
	 * Modular reduction: each high word in added/subtracted where
	 * necessary.
	 *
	 * The modulus is:
	 *    p = 2^256 - 2^224 + 2^192 + 2^96 - 1
	 * Therefore:
	 *    2^256 = 2^224 - 2^192 - 2^96 + 1 mod p
	 *
	 * For a word x at bit offset n (n >= 256), we have:
	 *    x*2^n = x*2^(n-32) - x*2^(n-64)
	 *            - x*2^(n - 160) + x*2^(n-256) mod p
	 *
	 * Thus, we can nullify the high word if we reinject it at some
	 * proper emplacements.
	 *
	 * We use 64-bit intermediate words to allow for carries to
	 * accumulate easily, before performing the final propagation.
	 */
	for (i = 0; i < 18; i++) {
		s[i] = t[i];
	}

	for (i = 17; i >= 9; i--) {
		uint64_t y;

		y = s[i];
		s[i - 1] += ARSHW(y, 2);
		s[i - 2] += (y << 28) & 0x3FFFFFFF;
		s[i - 2] -= ARSHW(y, 4);
		s[i - 3] -= (y << 26) & 0x3FFFFFFF;
		s[i - 5] -= ARSHW(y, 10);
		s[i - 6] -= (y << 20) & 0x3FFFFFFF;
		s[i - 8] += ARSHW(y, 16);
		s[i - 9] += (y << 14) & 0x3FFFFFFF;
	}

	/*
	 * Carry propagation must be signed. Moreover, we may have overdone
	 * it a bit, and obtain a negative result.
	 *
	 * The loop above ran 9 times; each time, each word was augmented
	 * by at most one extra word (in absolute value). Thus, the top
	 * word must in fine fit in 39 bits, so the carry below will fit
	 * on 9 bits.
	 */
	cc = 0;
	for (i = 0; i < 9; i++) {
		x = s[i] + cc;
		d[i] = (uint32_t)x & 0x3FFFFFFF;
		cc = ARSHW(x, 30);
	}

	/*
	 * All nine words fit on 30 bits, but there may be an extra
	 * carry for a few bits (at most 9), and that carry may be
	 * negative. Moreover, we want the result to fit on 257 bits.
	 * The two lines below ensure that the word in d[] has length
	 * 256 bits, and the (signed) carry (beyond 2^256) is in cc. The
	 * significant length of cc is less than 24 bits, so we will be
	 * able to switch to 32-bit operations.
	 */
	cc = ARSHW(x, 16);
	d[8] &= 0xFFFF;

	/*
	 * One extra round of reduction, for cc*2^256, which means
	 * adding cc*(2^224-2^192-2^96+1) to a 256-bit (nonnegative)
	 * value. If cc is negative, then it may happen (rarely, but
	 * not neglectibly so) that the result would be negative. In
	 * order to avoid that, if cc is negative, then we add the
	 * modulus once. Note that if cc is negative, then propagating
	 * that carry must yield a value lower than the modulus, so
	 * adding the modulus once will keep the final result under
	 * twice the modulus.
	 */
	z = (uint32_t)cc;
	d[3] -= z << 6;
	d[6] -= (z << 12) & 0x3FFFFFFF;
	d[7] -= ARSH(z, 18);
	d[7] += (z << 14) & 0x3FFFFFFF;
	d[8] += ARSH(z, 16);
	c = z >> 31;
	d[0] -= c;
	d[3] += c << 6;
	d[6] += c << 12;
	d[7] -= c << 14;
	d[8] += c << 16;
	for (i = 0; i < 9; i++) {
		uint32_t w;

		w = d[i] + z;
		d[i] = w & 0x3FFFFFFF;
		z = ARSH(w, 30);
	}
}

/*
 * Perform a "final reduction" in field F256 (field for curve P-256).
 * The source value must be less than twice the modulus. If the value
 * is not lower than the modulus, then the modulus is subtracted and
 * this function returns 1; otherwise, it leaves it untouched and it
 * returns 0.
 */
static uint32_t reduce_final_f256(uint32_t* d)
{
	uint32_t t[9];
	uint32_t cc;
	int i;

	cc = 0;
	for (i = 0; i < 9; i++) {
		uint32_t w;

		w = d[i] - F256[i] - cc;
		cc = w >> 31;
		t[i] = w & 0x3FFFFFFF;
	}
	cc ^= 1;
	CCOPY(cc, d, t, sizeof t);
	return cc;
}

/*
 * Compute one square root in F256. Source operand shall be less than
 * twice the modulus.
 */
static void sqrt_f256(uint32_t* d, const uint32_t* a)
{
	/*
	 * The base prime in P-256 is p = 3 (mod 4) so we can compute a
	 * square root by exponentiation to (p + 1) / 4. In P-256, this exponent is
	 * (p + 1) / 4 = 2^254 - 2^222 + 2^190 + 2^94
	 *         = 0x3fffffffc0000000400000000000000000000000400000000000000000000000
	 *
	 * We use an addition chain to compute this exponentiation. This
	 * addition chain can be calculated with
	 *    go install github.com/mmcloughlin/addchain/cmd/addchain@latest
	 *    addchain search 0x3fffffffc0000000400000000000000000000000400000000000000000000000
	 *
	 * resulting in
	 *
	 *   _10       = 2*1
	 *   _11       = 1 + _10
	 *   _1100     = _11 << 2
	 *   _1111     = _11 + _1100
	 *   _11110000 = _1111 << 4
	 *   _11111111 = _1111 + _11110000
	 *   x16       = _11111111 << 8 + _11111111
	 *   x32       = x16 << 16 + x16
	 *   return      ((x32 << 32 + 1) << 96 + 1) << 94
	 *
	 * Same approach as golang: https://cs.opensource.google/go/go/+/master:src/crypto/internal/nistec/p256.go;drc=a5cd894318677359f6d07ee74f9004d28b4d164c;l=459
	 */
	uint32_t t0[9];

	square_f256(d, a);
	mul_f256(d, d, a);
	square_f256(t0, d);
	for (int i = 1; i < 2; i++) {
		square_f256(t0, t0);
	}
	mul_f256(d, d, t0);
	square_f256(t0, d);
	for (int i = 1; i < 4; i++) {
		square_f256(t0, t0);
	}
	mul_f256(d, d, t0);
	square_f256(t0, d);
	for (int i = 1; i < 8; i++) {
		square_f256(t0, t0);
	}
	mul_f256(d, d, t0);
	square_f256(t0, d);
	for (int i = 1; i < 16; i++) {
		square_f256(t0, t0);
	}
	mul_f256(d, d, t0);
	for (int i = 0; i < 32; i++) {
		square_f256(d, d);
	}
	mul_f256(d, d, a);
	for (int i = 0; i < 96; i++) {
		square_f256(d, d);
	}
	mul_f256(d, d, a);
	for (int i = 0; i < 94; i++) {
		square_f256(d, d);
	}
}

/*
 * Jacobian coordinates for a point in P-256: affine coordinates (X,Y)
 * are such that:
 *   X = x / z^2
 *   Y = y / z^3
 * For the point at infinity, z = 0.
 * Each point thus admits many possible representations.
 *
 * Coordinates are represented in arrays of 32-bit integers, each holding
 * 30 bits of data. Values may also be slightly greater than the modulus,
 * but they will always be lower than twice the modulus.
 */
typedef struct {
	uint32_t x[9];
	uint32_t y[9];
	uint32_t z[9];
} p256_jacobian;

/*
 * Convert a point to affine coordinates:
 *  - If the point is the point at infinity, then all three coordinates
 *    are set to 0.
 *  - Otherwise, the 'z' coordinate is set to 1, and the 'x' and 'y'
 *    coordinates are the 'X' and 'Y' affine coordinates.
 * The coordinates are guaranteed to be lower than the modulus.
 */
static void p256_to_affine(p256_jacobian* P)
{
	uint32_t t1[9], t2[9];
	int i;

	/*
	 * Invert z with a modular exponentiation: the modulus is
	 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1, and the exponent is
	 * p-2. Exponent bit pattern (from high to low) is:
	 *  - 32 bits of value 1
	 *  - 31 bits of value 0
	 *  - 1 bit of value 1
	 *  - 96 bits of value 0
	 *  - 94 bits of value 1
	 *  - 1 bit of value 0
	 *  - 1 bit of value 1
	 * Thus, we precompute z^(2^31-1) to speed things up.
	 *
	 * If z = 0 (point at infinity) then the modular exponentiation
	 * will yield 0, which leads to the expected result (all three
	 * coordinates set to 0).
	 */

	 /*
	  * A simple square-and-multiply for z^(2^31-1). We could save about
	  * two dozen multiplications here with an addition chain, but
	  * this would require a bit more code, and extra stack buffers.
	  */
	memcpy(t1, P->z, sizeof P->z);
	for (i = 0; i < 30; i++) {
		square_f256(t1, t1);
		mul_f256(t1, t1, P->z);
	}

	/*
	 * Square-and-multiply. Apart from the squarings, we have a few
	 * multiplications to set bits to 1; we multiply by the original z
	 * for setting 1 bit, and by t1 for setting 31 bits.
	 */
	memcpy(t2, P->z, sizeof P->z);
	for (i = 1; i < 256; i++) {
		square_f256(t2, t2);
		switch (i) {
		case 31:
		case 190:
		case 221:
		case 252:
			mul_f256(t2, t2, t1);
			break;
		case 63:
		case 253:
		case 255:
			mul_f256(t2, t2, P->z);
			break;
		}
	}

	/*
	 * Now that we have 1/z, multiply x by 1/z^2 and y by 1/z^3.
	 */
	mul_f256(t1, t2, t2);
	mul_f256(P->x, t1, P->x);
	mul_f256(t1, t1, t2);
	mul_f256(P->y, t1, P->y);
	reduce_final_f256(P->x);
	reduce_final_f256(P->y);

	/*
	 * Multiply z by 1/z. If z = 0, then this will yield 0, otherwise
	 * this will set z to 1.
	 */
	mul_f256(P->z, P->z, t2);
	reduce_final_f256(P->z);
}

/*
 * Double a point in P-256. This function works for all valid points,
 * including the point at infinity.
 */
static void p256_double(p256_jacobian* Q)
{
	/*
	 * Doubling formulas are:
	 *
	 *   s = 4*x*y^2
	 *   m = 3*(x + z^2)*(x - z^2)
	 *   x' = m^2 - 2*s
	 *   y' = m*(s - x') - 8*y^4
	 *   z' = 2*y*z
	 *
	 * These formulas work for all points, including points of order 2
	 * and points at infinity:
	 *   - If y = 0 then z' = 0. But there is no such point in P-256
	 *     anyway.
	 *   - If z = 0 then z' = 0.
	 */
	uint32_t t1[9], t2[9], t3[9], t4[9];

	/*
	 * Compute z^2 in t1.
	 */
	square_f256(t1, Q->z);

	/*
	 * Compute x-z^2 in t2 and x+z^2 in t1.
	 */
	add_f256(t2, Q->x, t1);
	sub_f256(t1, Q->x, t1);

	/*
	 * Compute 3*(x+z^2)*(x-z^2) in t1.
	 */
	mul_f256(t3, t1, t2);
	add_f256(t1, t3, t3);
	add_f256(t1, t3, t1);

	/*
	 * Compute 4*x*y^2 (in t2) and 2*y^2 (in t3).
	 */
	square_f256(t3, Q->y);
	add_f256(t3, t3, t3);
	mul_f256(t2, Q->x, t3);
	add_f256(t2, t2, t2);

	/*
	 * Compute x' = m^2 - 2*s.
	 */
	square_f256(Q->x, t1);
	sub_f256(Q->x, Q->x, t2);
	sub_f256(Q->x, Q->x, t2);

	/*
	 * Compute z' = 2*y*z.
	 */
	mul_f256(t4, Q->y, Q->z);
	add_f256(Q->z, t4, t4);

	/*
	 * Compute y' = m*(s - x') - 8*y^4. Note that we already have
	 * 2*y^2 in t3.
	 */
	sub_f256(t2, t2, Q->x);
	mul_f256(Q->y, t1, t2);
	square_f256(t4, t3);
	add_f256(t4, t4, t4);
	sub_f256(Q->y, Q->y, t4);
}

/*
 * Add point P2 to point P1.
 *
 * This function computes the wrong result in the following cases:
 *
 *   - If P1 == 0 but P2 != 0
 *   - If P1 != 0 but P2 == 0
 *   - If P1 == P2
 *
 * In all three cases, P1 is set to the point at infinity.
 *
 * Returned value is 0 if one of the following occurs:
 *
 *   - P1 and P2 have the same Y coordinate
 *   - P1 == 0 and P2 == 0
 *   - The Y coordinate of one of the points is 0 and the other point is
 *     the point at infinity.
 *
 * The third case cannot actually happen with valid points, since a point
 * with Y == 0 is a point of order 2, and there is no point of order 2 on
 * curve P-256.
 *
 * Therefore, assuming that P1 != 0 and P2 != 0 on input, then the caller
 * can apply the following:
 *
 *   - If the result is not the point at infinity, then it is correct.
 *   - Otherwise, if the returned value is 1, then this is a case of
 *     P1+P2 == 0, so the result is indeed the point at infinity.
 *   - Otherwise, P1 == P2, so a "double" operation should have been
 *     performed.
 */
static uint32_t p256_add(p256_jacobian* P1, const p256_jacobian* P2)
{
	/*
	 * Addtions formulas are:
	 *
	 *   u1 = x1 * z2^2
	 *   u2 = x2 * z1^2
	 *   s1 = y1 * z2^3
	 *   s2 = y2 * z1^3
	 *   h = u2 - u1
	 *   r = s2 - s1
	 *   x3 = r^2 - h^3 - 2 * u1 * h^2
	 *   y3 = r * (u1 * h^2 - x3) - s1 * h^3
	 *   z3 = h * z1 * z2
	 */
	uint32_t t1[9], t2[9], t3[9], t4[9], t5[9], t6[9], t7[9];
	uint32_t ret;
	int i;

	/*
	 * Compute u1 = x1*z2^2 (in t1) and s1 = y1*z2^3 (in t3).
	 */
	square_f256(t3, P2->z);
	mul_f256(t1, P1->x, t3);
	mul_f256(t4, P2->z, t3);
	mul_f256(t3, P1->y, t4);

	/*
	 * Compute u2 = x2*z1^2 (in t2) and s2 = y2*z1^3 (in t4).
	 */
	square_f256(t4, P1->z);
	mul_f256(t2, P2->x, t4);
	mul_f256(t5, P1->z, t4);
	mul_f256(t4, P2->y, t5);

	/*
	 * Compute h = h2 - u1 (in t2) and r = s2 - s1 (in t4).
	 * We need to test whether r is zero, so we will do some extra
	 * reduce.
	 */
	sub_f256(t2, t2, t1);
	sub_f256(t4, t4, t3);
	reduce_final_f256(t4);
	ret = 0;
	for (i = 0; i < 9; i++) {
		ret |= t4[i];
	}
	ret = (ret | -ret) >> 31;

	/*
	 * Compute u1*h^2 (in t6) and h^3 (in t5);
	 */
	square_f256(t7, t2);
	mul_f256(t6, t1, t7);
	mul_f256(t5, t7, t2);

	/*
	 * Compute x3 = r^2 - h^3 - 2*u1*h^2.
	 */
	square_f256(P1->x, t4);
	sub_f256(P1->x, P1->x, t5);
	sub_f256(P1->x, P1->x, t6);
	sub_f256(P1->x, P1->x, t6);

	/*
	 * Compute y3 = r*(u1*h^2 - x3) - s1*h^3.
	 */
	sub_f256(t6, t6, P1->x);
	mul_f256(P1->y, t4, t6);
	mul_f256(t1, t5, t3);
	sub_f256(P1->y, P1->y, t1);

	/*
	 * Compute z3 = h*z1*z2.
	 */
	mul_f256(t1, P1->z, P2->z);
	mul_f256(P1->z, t1, t2);

	return ret;
}

/*
 * Add point P2 to point P1. This is a specialised function for the
 * case when P2 is a non-zero point in affine coordinate.
 *
 * This function computes the wrong result in the following cases:
 *
 *   - If P1 == 0
 *   - If P1 == P2
 *
 * In both cases, P1 is set to the point at infinity.
 *
 * Returned value is 0 if one of the following occurs:
 *
 *   - P1 and P2 have the same Y coordinate
 *   - The Y coordinate of P2 is 0 and P1 is the point at infinity.
 *
 * The second case cannot actually happen with valid points, since a point
 * with Y == 0 is a point of order 2, and there is no point of order 2 on
 * curve P-256.
 *
 * Therefore, assuming that P1 != 0 on input, then the caller
 * can apply the following:
 *
 *   - If the result is not the point at infinity, then it is correct.
 *   - Otherwise, if the returned value is 1, then this is a case of
 *     P1+P2 == 0, so the result is indeed the point at infinity.
 *   - Otherwise, P1 == P2, so a "double" operation should have been
 *     performed.
 */
static uint32_t p256_add_mixed(p256_jacobian* P1, const p256_jacobian* P2)
{
	/*
	 * Addtions formulas are:
	 *
	 *   u1 = x1
	 *   u2 = x2 * z1^2
	 *   s1 = y1
	 *   s2 = y2 * z1^3
	 *   h = u2 - u1
	 *   r = s2 - s1
	 *   x3 = r^2 - h^3 - 2 * u1 * h^2
	 *   y3 = r * (u1 * h^2 - x3) - s1 * h^3
	 *   z3 = h * z1
	 */
	uint32_t t1[9], t2[9], t3[9], t4[9], t5[9], t6[9], t7[9];
	uint32_t ret;
	int i;

	/*
	 * Compute u1 = x1 (in t1) and s1 = y1 (in t3).
	 */
	memcpy(t1, P1->x, sizeof t1);
	memcpy(t3, P1->y, sizeof t3);

	/*
	 * Compute u2 = x2*z1^2 (in t2) and s2 = y2*z1^3 (in t4).
	 */
	square_f256(t4, P1->z);
	mul_f256(t2, P2->x, t4);
	mul_f256(t5, P1->z, t4);
	mul_f256(t4, P2->y, t5);

	/*
	 * Compute h = h2 - u1 (in t2) and r = s2 - s1 (in t4).
	 * We need to test whether r is zero, so we will do some extra
	 * reduce.
	 */
	sub_f256(t2, t2, t1);
	sub_f256(t4, t4, t3);
	reduce_final_f256(t4);
	ret = 0;
	for (i = 0; i < 9; i++) {
		ret |= t4[i];
	}
	ret = (ret | -ret) >> 31;

	/*
	 * Compute u1*h^2 (in t6) and h^3 (in t5);
	 */
	square_f256(t7, t2);
	mul_f256(t6, t1, t7);
	mul_f256(t5, t7, t2);

	/*
	 * Compute x3 = r^2 - h^3 - 2*u1*h^2.
	 */
	square_f256(P1->x, t4);
	sub_f256(P1->x, P1->x, t5);
	sub_f256(P1->x, P1->x, t6);
	sub_f256(P1->x, P1->x, t6);

	/*
	 * Compute y3 = r*(u1*h^2 - x3) - s1*h^3.
	 */
	sub_f256(t6, t6, P1->x);
	mul_f256(P1->y, t4, t6);
	mul_f256(t1, t5, t3);
	sub_f256(P1->y, P1->y, t1);

	/*
	 * Compute z3 = h*z1*z2.
	 */
	mul_f256(P1->z, P1->z, t2);

	return ret;
}

static uint32_t
p256_decode_uncompressed(p256_jacobian* P, const void* src, size_t len)
{
	const unsigned char* buf;
	uint32_t tx[9], ty[9], t1[9], t2[9];
	uint32_t bad;
	int i;

	if (len != 65) {
		return 0;
	}
	buf = (unsigned char*)src;

	/*
	 * First byte must be 0x04 (uncompressed format). We could support
	 * "hybrid format" (first byte is 0x06 or 0x07, and encodes the
	 * least significant bit of the Y coordinate), but it is explicitly
	 * forbidden by RFC 5480 (section 2.2).
	 */
	bad = NEQ(buf[0], 0x04);

	/*
	 * Decode the coordinates, and check that they are both lower
	 * than the modulus.
	 */
	tx[8] = be8_to_le30(tx, buf + 1, 32);
	ty[8] = be8_to_le30(ty, buf + 33, 32);
	bad |= reduce_final_f256(tx);
	bad |= reduce_final_f256(ty);

	/*
	 * Check curve equation.
	 */
	square_f256(t1, tx);
	mul_f256(t1, tx, t1);
	square_f256(t2, ty);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	add_f256(t1, t1, P256_B);
	sub_f256(t1, t1, t2);
	reduce_final_f256(t1);
	for (i = 0; i < 9; i++) {
		bad |= t1[i];
	}

	/*
	 * Copy coordinates to the point structure.
	 */
	memcpy(P->x, tx, sizeof tx);
	memcpy(P->y, ty, sizeof ty);
	memset(P->z, 0, sizeof P->z);
	P->z[0] = 1;
	return NEQ(bad, 0) ^ 1;
}

static uint32_t p256_decode_compressed(p256_jacobian* P, const void* src, size_t len)
{
	/*
	 * Reference: https://www.secg.org/sec1-v2.pdf section 2.3.4
	 * "Octet-String-to-Elliptic-Curve-Point Conversion"
	 */
	const unsigned char* buf;
	uint32_t tx[9], ty[9], t1[9], t2[9];
	uint32_t bad;
	int i;

	if (len != 33) {
		return 0;
	}
	buf = (unsigned char*)src;

	/*
	 * First byte must be 0x02 or 0x03 (compressed format).
	 */
	bad = NEQ(buf[0], 0x02) & NEQ(buf[0], 0x03);

	/*
	 * Decode the x coordinate, and check that it is lower
	 * than the modulus.
	 */
	tx[8] = be8_to_le30(tx, buf + 1, 32);
	bad |= reduce_final_f256(tx);

	/*
	 * Derive a field element \alpha from curve equation.
	 * In the happy path, \alpha is a square, y^2.
	 */
	square_f256(t1, tx);
	mul_f256(t1, tx, t1);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	add_f256(t1, t1, P256_B);

	/*
	 * Take one square root of \alpha.
	 * This is either y or -y in the happy path.
	 */
	sqrt_f256(ty, t1);
	reduce_final_f256(ty);

	/*
	 * Pick the square root signaled by sender in src[0]&1.
	 */
	uint32_t need_swap = NEQ(buf[0] & 1, ty[0] & 1);
	sub_f256(t1, F256, ty);
	reduce_final_f256(t1);
	CCOPY(need_swap, ty, t1, sizeof t1);

	/*
	 * Check curve equation.
	 */
	square_f256(t1, tx);
	mul_f256(t1, tx, t1);
	square_f256(t2, ty);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	sub_f256(t1, t1, tx);
	add_f256(t1, t1, P256_B);
	sub_f256(t1, t1, t2);
	reduce_final_f256(t1);
	for (i = 0; i < 9; i++) {
		bad |= t1[i];
	}

	/*
	 * Copy coordinates to the point structure.
	 */
	memcpy(P->x, tx, sizeof tx);
	memcpy(P->y, ty, sizeof ty);
	memset(P->z, 0, sizeof P->z);
	P->z[0] = 1;
	return NEQ(bad, 0) ^ 1;
}

/*
 * Decode a P-256 point. This function does not support the point at
 * infinity. Returned value is 0 if the point is invalid, 1 otherwise.
 */
static uint32_t p256_decode(p256_jacobian* P, const void* src, size_t len)
{
	uint32_t valid1 = p256_decode_uncompressed(P, src, len);
	uint32_t valid2 = p256_decode_compressed(P, src, len);
	return valid1 | valid2;
}

/*
 * Encode a point into a buffer. This function assumes that the point is
 * valid, in affine coordinates, and not the point at infinity.
 */
static void p256_encode(void* dst, const p256_jacobian* P)
{
	unsigned char* buf;

	buf = (unsigned char*)dst;
	buf[0] = 0x04;
	le30_to_be8(buf + 1, 32, P->x);
	le30_to_be8(buf + 33, 32, P->y);
}

/*
 * Multiply a curve point by an integer. The integer is assumed to be
 * lower than the curve order, and the base point must not be the point
 * at infinity.
 */
static void p256_mul(p256_jacobian* P, const unsigned char* x, size_t xlen)
{
	/*
	 * qz is a flag that is initially 1, and remains equal to 1
	 * as long as the point is the point at infinity.
	 *
	 * We use a 2-bit window to handle multiplier bits by pairs.
	 * The precomputed window really is the points P2 and P3.
	 */
	uint32_t qz;
	p256_jacobian P2, P3, Q, T, U;

	/*
	 * Compute window values.
	 */
	P2 = *P;
	p256_double(&P2);
	P3 = *P;
	p256_add(&P3, &P2);

	/*
	 * We start with Q = 0. We process multiplier bits 2 by 2.
	 */
	memset(&Q, 0, sizeof Q);
	qz = 1;
	while (xlen-- > 0) {
		int k;

		for (k = 6; k >= 0; k -= 2) {
			uint32_t bits;
			uint32_t bnz;

			p256_double(&Q);
			p256_double(&Q);
			T = *P;
			U = Q;
			bits = (*x >> k) & (uint32_t)3;
			bnz = NEQ(bits, 0);
			CCOPY(EQ(bits, 2), &T, &P2, sizeof T);
			CCOPY(EQ(bits, 3), &T, &P3, sizeof T);
			p256_add(&U, &T);
			CCOPY(bnz & qz, &Q, &T, sizeof Q);
			CCOPY(bnz & ~qz, &Q, &U, sizeof Q);
			qz &= ~bnz;
		}
		x++;
	}
	*P = Q;
}

/*
 * Precomputed window: k*G points, where G is the curve generator, and k
 * is an integer from 1 to 15 (inclusive). The X and Y coordinates of
 * the point are encoded as 9 words of 30 bits each (little-endian
 * order).
 */
static const uint32_t Gwin[15][18] = {

	{ 0x1898C296, 0x1284E517, 0x1EB33A0F, 0x00DF604B,
	  0x2440F277, 0x339B958E, 0x04247F8B, 0x347CB84B,
	  0x00006B17, 0x37BF51F5, 0x2ED901A0, 0x3315ECEC,
	  0x338CD5DA, 0x0F9E162B, 0x1FAD29F0, 0x27F9B8EE,
	  0x10B8BF86, 0x00004FE3 },

	{ 0x07669978, 0x182D23F1, 0x3F21B35A, 0x225A789D,
	  0x351AC3C0, 0x08E00C12, 0x34F7E8A5, 0x1EC62340,
	  0x00007CF2, 0x227873D1, 0x3812DE74, 0x0E982299,
	  0x1F6B798F, 0x3430DBBA, 0x366B1A7D, 0x2D040293,
	  0x154436E3, 0x00000777 },

	{ 0x06E7FD6C, 0x2D05986F, 0x3ADA985F, 0x31ADC87B,
	  0x0BF165E6, 0x1FBE5475, 0x30A44C8F, 0x3934698C,
	  0x00005ECB, 0x227D5032, 0x29E6C49E, 0x04FB83D9,
	  0x0AAC0D8E, 0x24A2ECD8, 0x2C1B3869, 0x0FF7E374,
	  0x19031266, 0x00008734 },

	{ 0x2B030852, 0x024C0911, 0x05596EF5, 0x07F8B6DE,
	  0x262BD003, 0x3779967B, 0x08FBBA02, 0x128D4CB4,
	  0x0000E253, 0x184ED8C6, 0x310B08FC, 0x30EE0055,
	  0x3F25B0FC, 0x062D764E, 0x3FB97F6A, 0x33CC719D,
	  0x15D69318, 0x0000E0F1 },

	{ 0x03D033ED, 0x05552837, 0x35BE5242, 0x2320BF47,
	  0x268FDFEF, 0x13215821, 0x140D2D78, 0x02DE9454,
	  0x00005159, 0x3DA16DA4, 0x0742ED13, 0x0D80888D,
	  0x004BC035, 0x0A79260D, 0x06FCDAFE, 0x2727D8AE,
	  0x1F6A2412, 0x0000E0C1 },

	{ 0x3C2291A9, 0x1AC2ABA4, 0x3B215B4C, 0x131D037A,
	  0x17DDE302, 0x0C90B2E2, 0x0602C92D, 0x05CA9DA9,
	  0x0000B01A, 0x0FC77FE2, 0x35F1214E, 0x07E16BDF,
	  0x003DDC07, 0x2703791C, 0x3038B7EE, 0x3DAD56FE,
	  0x041D0C8D, 0x0000E85C },

	{ 0x3187B2A3, 0x0018A1C0, 0x00FEF5B3, 0x3E7E2E2A,
	  0x01FB607E, 0x2CC199F0, 0x37B4625B, 0x0EDBE82F,
	  0x00008E53, 0x01F400B4, 0x15786A1B, 0x3041B21C,
	  0x31CD8CF2, 0x35900053, 0x1A7E0E9B, 0x318366D0,
	  0x076F780C, 0x000073EB },

	{ 0x1B6FB393, 0x13767707, 0x3CE97DBB, 0x348E2603,
	  0x354CADC1, 0x09D0B4EA, 0x1B053404, 0x1DE76FBA,
	  0x000062D9, 0x0F09957E, 0x295029A8, 0x3E76A78D,
	  0x3B547DAE, 0x27CEE0A2, 0x0575DC45, 0x1D8244FF,
	  0x332F647A, 0x0000AD5A },

	{ 0x10949EE0, 0x1E7A292E, 0x06DF8B3D, 0x02B2E30B,
	  0x31F8729E, 0x24E35475, 0x30B71878, 0x35EDBFB7,
	  0x0000EA68, 0x0DD048FA, 0x21688929, 0x0DE823FE,
	  0x1C53FAA9, 0x0EA0C84D, 0x052A592A, 0x1FCE7870,
	  0x11325CB2, 0x00002A27 },

	{ 0x04C5723F, 0x30D81A50, 0x048306E4, 0x329B11C7,
	  0x223FB545, 0x085347A8, 0x2993E591, 0x1B5ACA8E,
	  0x0000CEF6, 0x04AF0773, 0x28D2EEA9, 0x2751EEEC,
	  0x037B4A7F, 0x3B4C1059, 0x08F37674, 0x2AE906E1,
	  0x18A88A6A, 0x00008786 },

	{ 0x34BC21D1, 0x0CCE474D, 0x15048BF4, 0x1D0BB409,
	  0x021CDA16, 0x20DE76C3, 0x34C59063, 0x04EDE20E,
	  0x00003ED1, 0x282A3740, 0x0BE3BBF3, 0x29889DAE,
	  0x03413697, 0x34C68A09, 0x210EBE93, 0x0C8A224C,
	  0x0826B331, 0x00009099 },

	{ 0x0624E3C4, 0x140317BA, 0x2F82C99D, 0x260C0A2C,
	  0x25D55179, 0x194DCC83, 0x3D95E462, 0x356F6A05,
	  0x0000741D, 0x0D4481D3, 0x2657FC8B, 0x1BA5CA71,
	  0x3AE44B0D, 0x07B1548E, 0x0E0D5522, 0x05FDC567,
	  0x2D1AA70E, 0x00000770 },

	{ 0x06072C01, 0x23857675, 0x1EAD58A9, 0x0B8A12D9,
	  0x1EE2FC79, 0x0177CB61, 0x0495A618, 0x20DEB82B,
	  0x0000177C, 0x2FC7BFD8, 0x310EEF8B, 0x1FB4DF39,
	  0x3B8530E8, 0x0F4E7226, 0x0246B6D0, 0x2A558A24,
	  0x163353AF, 0x000063BB },

	{ 0x24D2920B, 0x1C249DCC, 0x2069C5E5, 0x09AB2F9E,
	  0x36DF3CF1, 0x1991FD0C, 0x062B97A7, 0x1E80070E,
	  0x000054E7, 0x20D0B375, 0x2E9F20BD, 0x35090081,
	  0x1C7A9DDC, 0x22E7C371, 0x087E3016, 0x03175421,
	  0x3C6ECA7D, 0x0000F599 },

	{ 0x259B9D5F, 0x0D9A318F, 0x23A0EF16, 0x00EBE4B7,
	  0x088265AE, 0x2CDE2666, 0x2BAE7ADF, 0x1371A5C6,
	  0x0000F045, 0x0D034F36, 0x1F967378, 0x1B5FA3F4,
	  0x0EC8739D, 0x1643E62A, 0x1653947E, 0x22D1F4E6,
	  0x0FB8D64B, 0x0000B5B9 }
};

/*
 * Lookup one of the Gwin[] values, by index. This is constant-time.
 */
static void lookup_Gwin(p256_jacobian* T, uint32_t idx)
{
	uint32_t xy[18];
	uint32_t k;
	size_t u;

	memset(xy, 0, sizeof xy);
	for (k = 0; k < 15; k++) {
		uint32_t m;

		m = -EQ(idx, k + 1);
		for (u = 0; u < 18; u++) {
			xy[u] |= m & Gwin[k][u];
		}
	}
	memcpy(T->x, &xy[0], sizeof T->x);
	memcpy(T->y, &xy[9], sizeof T->y);
	memset(T->z, 0, sizeof T->z);
	T->z[0] = 1;
}

/*
 * Multiply the generator by an integer. The integer is assumed non-zero
 * and lower than the curve order.
 */
static void p256_mulgen(p256_jacobian* P, const unsigned char* x, size_t xlen)
{
	/*
	 * qz is a flag that is initially 1, and remains equal to 1
	 * as long as the point is the point at infinity.
	 *
	 * We use a 4-bit window to handle multiplier bits by groups
	 * of 4. The precomputed window is constant static data, with
	 * points in affine coordinates; we use a constant-time lookup.
	 */
	p256_jacobian Q;
	uint32_t qz;

	memset(&Q, 0, sizeof Q);
	qz = 1;
	while (xlen-- > 0) {
		int k;
		unsigned bx;

		bx = *x++;
		for (k = 0; k < 2; k++) {
			uint32_t bits;
			uint32_t bnz;
			p256_jacobian T, U;

			p256_double(&Q);
			p256_double(&Q);
			p256_double(&Q);
			p256_double(&Q);
			bits = (bx >> 4) & 0x0F;
			bnz = NEQ(bits, 0);
			lookup_Gwin(&T, bits);
			U = Q;
			p256_add_mixed(&U, &T);
			CCOPY(bnz & qz, &Q, &T, sizeof Q);
			CCOPY(bnz & ~qz, &Q, &U, sizeof Q);
			qz &= ~bnz;
			bx <<= 4;
		}
	}
	*P = Q;
}

static const unsigned char P256_G[] = {
	0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8,
	0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
	0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
	0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
	0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B,
	0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
	0x68, 0x37, 0xBF, 0x51, 0xF5
};

static const unsigned char P256_N[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD,
	0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
	0x25, 0x51
};

static const unsigned char* api_generator(int curve, size_t* len)
{
	(void)curve;
	*len = sizeof P256_G;
	return P256_G;
}

static const unsigned char* api_order(int curve, size_t* len)
{
	(void)curve;
	*len = sizeof P256_N;
	return P256_N;
}

static size_t api_xoff(int curve, size_t* len)
{
	(void)curve;
	*len = 32;
	return 1;
}

static uint32_t api_mul(unsigned char* G, size_t Glen,
	const unsigned char* x, size_t xlen, int curve)
{
	uint32_t r;
	p256_jacobian P;

	(void)curve;
	r = p256_decode(&P, G, Glen);
	p256_mul(&P, x, xlen);
	if (Glen >= 65) {
		p256_to_affine(&P);
		p256_encode(G, &P);
	}
	return r;
}

static size_t api_mulgen(unsigned char* R,
	const unsigned char* x, size_t xlen, int curve)
{
	p256_jacobian P;

	(void)curve;
	p256_mulgen(&P, x, xlen);
	p256_to_affine(&P);
	p256_encode(R, &P);
	return 65;

	/*
	const unsigned char *G;
	size_t Glen;

	G = api_generator(curve, &Glen);
	memcpy(R, G, Glen);
	api_mul(R, Glen, x, xlen, curve);
	return Glen;
	*/
}

static uint32_t api_muladd(unsigned char* A, const unsigned char* B, size_t len,
	const unsigned char* x, size_t xlen, const unsigned char* y, size_t ylen, int curve)
{
	p256_jacobian P, Q;
	uint32_t r, t, z;
	int i;

	(void)curve;
	r = p256_decode(&P, A, len);
	p256_mul(&P, x, xlen);
	if (B == NULL) {
		p256_mulgen(&Q, y, ylen);
	}
	else {
		r &= p256_decode(&Q, B, len);
		p256_mul(&Q, y, ylen);
	}

	/*
	 * The final addition may fail in case both points are equal.
	 */
	t = p256_add(&P, &Q);
	reduce_final_f256(P.z);
	z = 0;
	for (i = 0; i < 9; i++) {
		z |= P.z[i];
	}
	z = EQ(z, 0);
	p256_double(&Q);

	/*
	 * If z is 1 then either P+Q = 0 (t = 1) or P = Q (t = 0). So we
	 * have the following:
	 *
	 *   z = 0, t = 0   return P (normal addition)
	 *   z = 0, t = 1   return P (normal addition)
	 *   z = 1, t = 0   return Q (a 'double' case)
	 *   z = 1, t = 1   report an error (P+Q = 0)
	 */
	CCOPY(z & ~t, &P, &Q, sizeof Q);
	p256_to_affine(&P);
	p256_encode(A, &P);
	r &= ~(z & t);
	return r;
}

/* see bearssl_ec.h */
const br_ec_impl br_ec_p256_m31 = {
	(uint32_t)0x00800000,
	&api_generator,
	&api_order,
	&api_xoff,
	&api_mul,
	&api_mulgen,
	&api_muladd
};


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static void br_ecdsa_i31_bits2int(uint32_t* x,
	const void* src, size_t len, uint32_t ebitlen)
{
	uint32_t bitlen, hbitlen;
	int sc;

	bitlen = ebitlen - (ebitlen >> 5);
	hbitlen = (uint32_t)len << 3;
	if (hbitlen > bitlen) {
		len = (bitlen + 7) >> 3;
		sc = (int)((hbitlen - bitlen) & 7);
	}
	else {
		sc = 0;
	}
	br_i31_zero(x, ebitlen);
	br_i31_decode(x, src, len);
	br_i31_rshift(x, sc);
	x[0] = ebitlen;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


#define I31_LEN     ((BR_MAX_EC_SIZE + 61) / 31)
#define POINT_LEN   (1 + (((BR_MAX_EC_SIZE + 7) >> 3) << 1))

 /* see bearssl_ec.h */
static uint32_t br_ecdsa_i31_vrfy_raw(const br_ec_impl* impl,
	const void* hash, size_t hash_len,
	const br_ec_public_key* pk,
	const void* sig, size_t sig_len)
{
	/*
	 * IMPORTANT: this code is fit only for curves with a prime
	 * order. This is needed so that modular reduction of the X
	 * coordinate of a point can be done with a simple subtraction.
	 */
	const br_ec_curve_def* cd;
	uint32_t n[I31_LEN], r[I31_LEN], s[I31_LEN], t1[I31_LEN], t2[I31_LEN];
	unsigned char tx[(BR_MAX_EC_SIZE + 7) >> 3];
	unsigned char ty[(BR_MAX_EC_SIZE + 7) >> 3];
	unsigned char eU[POINT_LEN];
	size_t nlen, rlen, ulen;
	uint32_t n0i, res;

	/*
	 * If the curve is not supported, then report an error.
	 */
	if (((impl->supported_curves >> pk->curve) & 1) == 0) {
		return 0;
	}

	/*
	 * Get the curve parameters (generator and order).
	 */
	switch (pk->curve) {
	case BR_EC_secp256r1:
		cd = &br_secp256r1;
		break;
		/*
			case BR_EC_secp384r1:
				cd = &br_secp384r1;
				break;
			case BR_EC_secp521r1:
				cd = &br_secp521r1;
				break;
		*/
	default:
		return 0;
	}

	/*
	 * Signature length must be even.
	 */
	if (sig_len & 1) {
		return 0;
	}
	rlen = sig_len >> 1;

	/*
	 * Public key point must have the proper size for this curve.
	 */
	if ((pk->qlen != cd->generator_len) /* uncompressed */ &&
		(pk->qlen != (cd->generator_len / 2) + 1) /* compressed */) {
		return 0;
	}

	/*
	 * Get modulus; then decode the r and s values. They must be
	 * lower than the modulus, and s must not be null.
	 */
	nlen = cd->order_len;
	br_i31_decode(n, cd->order, nlen);
	n0i = br_i31_ninv31(n[1]);
	if (!br_i31_decode_mod(r, sig, rlen, n)) {
		return 0;
	}
	if (!br_i31_decode_mod(s, (const unsigned char*)sig + rlen, rlen, n)) {
		return 0;
	}
	if (br_i31_iszero(s)) {
		return 0;
	}

	/*
	 * Invert s. We do that with a modular exponentiation; we use
	 * the fact that for all the curves we support, the least
	 * significant byte is not 0 or 1, so we can subtract 2 without
	 * any carry to process.
	 * We also want 1/s in Montgomery representation, which can be
	 * done by converting _from_ Montgomery representation before
	 * the inversion (because (1/s)*R = 1/(s/R)).
	 */
	br_i31_from_monty(s, n, n0i);
	memcpy(tx, cd->order, nlen);
	tx[nlen - 1] -= 2;
	br_i31_modpow(s, tx, nlen, n, n0i, t1, t2);

	/*
	 * Truncate the hash to the modulus length (in bits) and reduce
	 * it modulo the curve order. The modular reduction can be done
	 * with a subtraction since the truncation already reduced the
	 * value to the modulus bit length.
	 */
	br_ecdsa_i31_bits2int(t1, hash, hash_len, n[0]);
	br_i31_sub(t1, n, br_i31_sub(t1, n, 0) ^ 1);

	/*
	 * Multiply the (truncated, reduced) hash value with 1/s, result in
	 * t2, encoded in ty.
	 */
	br_i31_montymul(t2, t1, s, n, n0i);
	br_i31_encode(ty, nlen, t2);

	/*
	 * Multiply r with 1/s, result in t1, encoded in tx.
	 */
	br_i31_montymul(t1, r, s, n, n0i);
	br_i31_encode(tx, nlen, t1);

	/*
	 * Compute the point x*Q + y*G.
	 */
	ulen = cd->generator_len;
	memset(eU, 0, ulen);
	memcpy(eU, pk->q, pk->qlen);
	res = impl->muladd(eU, NULL, pk->qlen,
		tx, nlen, ty, nlen, cd->curve);

	/*
	 * Get the X coordinate, reduce modulo the curve order, and
	 * compare with the 'r' value.
	 *
	 * The modular reduction can be done with subtractions because
	 * we work with curves of prime order, so the curve order is
	 * close to the field order (Hasse's theorem).
	 */
	br_i31_zero(t1, n[0]);
	br_i31_decode(t1, &eU[1], ulen >> 1);
	t1[0] = n[0];
	br_i31_sub(t1, n, br_i31_sub(t1, n, 0) ^ 1);
	res &= ~br_i31_sub(t1, r, 1);
	res &= br_i31_iszero(t1);
	return res;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static void br_range_enc32be(void* dst, const uint32_t* v, size_t num)
{
	unsigned char* buf;

	buf = (unsigned char*)dst;
	while (num-- > 0) {
		br_enc32be(buf, *v++);
		buf += 4;
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static uint32_t br_i31_add(uint32_t* a, const uint32_t* b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 63) >> 5;
	for (u = 1; u < m; u++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw + bw + cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & (uint32_t)0x7FFFFFFF, aw);
	}
	return cc;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static uint32_t br_i31_bit_length(uint32_t* x, size_t xlen)
{
	uint32_t tw, twk;

	tw = 0;
	twk = 0;
	while (xlen-- > 0) {
		uint32_t w, c;

		c = EQ(tw, 0);
		w = x[xlen];
		tw = MUX(c, w, tw);
		twk = MUX(c, (uint32_t)xlen, twk);
	}
	return (twk << 5) + BIT_LENGTH(tw);
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static uint32_t br_i31_decode_mod(uint32_t* x, const void* src, size_t len, const uint32_t* m)
{
	/*
	 * Two-pass algorithm: in the first pass, we determine whether the
	 * value fits; in the second pass, we do the actual write.
	 *
	 * During the first pass, 'r' contains the comparison result so
	 * far:
	 *  0x00000000   value is equal to the modulus
	 *  0x00000001   value is greater than the modulus
	 *  0xFFFFFFFF   value is lower than the modulus
	 *
	 * Since we iterate starting with the least significant bytes (at
	 * the end of src[]), each new comparison overrides the previous
	 * except when the comparison yields 0 (equal).
	 *
	 * During the second pass, 'r' is either 0xFFFFFFFF (value fits)
	 * or 0x00000000 (value does not fit).
	 *
	 * We must iterate over all bytes of the source, _and_ possibly
	 * some extra virtual bytes (with value 0) so as to cover the
	 * complete modulus as well. We also add 4 such extra bytes beyond
	 * the modulus length because it then guarantees that no accumulated
	 * partial word remains to be processed.
	 */
	const unsigned char* buf;
	size_t mlen, tlen;
	int pass;
	uint32_t r;

	buf = (unsigned char*)src;
	mlen = (m[0] + 31) >> 5;
	tlen = (mlen << 2);
	if (tlen < len) {
		tlen = len;
	}
	tlen += 4;
	r = 0;
	for (pass = 0; pass < 2; pass++) {
		size_t u, v;
		uint32_t acc;
		int acc_len;

		v = 1;
		acc = 0;
		acc_len = 0;
		for (u = 0; u < tlen; u++) {
			uint32_t b;

			if (u < len) {
				b = buf[len - 1 - u];
			}
			else {
				b = 0;
			}
			acc |= (b << acc_len);
			acc_len += 8;
			if (acc_len >= 31) {
				uint32_t xw;

				xw = acc & (uint32_t)0x7FFFFFFF;
				acc_len -= 31;
				acc = b >> (8 - acc_len);
				if (v <= mlen) {
					if (pass) {
						x[v] = r & xw;
					}
					else {
						uint32_t cc;

						cc = (uint32_t)CMP(xw, m[v]);
						r = MUX(EQ(cc, 0), r, cc);
					}
				}
				else {
					if (!pass) {
						r = MUX(EQ(xw, 0), r, 1);
					}
				}
				v++;
			}
		}

		/*
		 * When we reach this point at the end of the first pass:
		 * r is either 0, 1 or -1; we want to set r to 0 if it
		 * is equal to 0 or 1, and leave it to -1 otherwise.
		 *
		 * When we reach this point at the end of the second pass:
		 * r is either 0 or -1; we want to leave that value
		 * untouched. This is a subcase of the previous.
		 */
		r >>= 1;
		r |= (r << 1);
	}

	x[0] = m[0];
	return r & (uint32_t)1;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_decode(uint32_t* x, const void* src, size_t len)
{
	const unsigned char* buf;
	size_t u, v;
	uint32_t acc;
	int acc_len;

	buf = (unsigned char*)src;
	u = len;
	v = 1;
	acc = 0;
	acc_len = 0;
	while (u-- > 0) {
		uint32_t b;

		b = buf[u];
		acc |= (b << acc_len);
		acc_len += 8;
		if (acc_len >= 31) {
			x[v++] = acc & (uint32_t)0x7FFFFFFF;
			acc_len -= 31;
			acc = b >> (8 - acc_len);
		}
	}
	if (acc_len != 0) {
		x[v++] = acc;
	}
	x[0] = br_i31_bit_length(x + 1, v - 1);
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_encode(void* dst, size_t len, const uint32_t* x)
{
	unsigned char* buf;
	size_t k, xlen;
	uint32_t acc;
	int acc_len;

	xlen = (x[0] + 31) >> 5;
	if (xlen == 0) {
		memset(dst, 0, len);
		return;
	}
	buf = (unsigned char*)dst + len;
	k = 1;
	acc = 0;
	acc_len = 0;
	while (len != 0) {
		uint32_t w;

		w = (k <= xlen) ? x[k] : 0;
		k++;
		if (acc_len == 0) {
			acc = w;
			acc_len = 31;
		}
		else {
			uint32_t z;

			z = acc | (w << acc_len);
			acc_len--;
			acc = w >> (31 - acc_len);
			if (len >= 4) {
				buf -= 4;
				len -= 4;
				br_enc32be(buf, z);
			}
			else {
				switch (len) {
				case 3:
					buf[-3] = (unsigned char)(z >> 16);
					/* fall through */
				case 2:
					buf[-2] = (unsigned char)(z >> 8);
					/* fall through */
				case 1:
					buf[-1] = (unsigned char)z;
					break;
				}
				return;
			}
		}
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_from_monty(uint32_t* x, const uint32_t* m, uint32_t m0i)
{
	size_t len, u, v;

	len = (m[0] + 31) >> 5;
	for (u = 0; u < len; u++) {
		uint32_t f;
		uint64_t cc;

		f = MUL31_lo(x[1], m0i);
		cc = 0;
		for (v = 0; v < len; v++) {
			uint64_t z;

			z = (uint64_t)x[v + 1] + MUL31(f, m[v + 1]) + cc;
			cc = z >> 31;
			if (v != 0) {
				x[v] = (uint32_t)z & 0x7FFFFFFF;
			}
		}
		x[len] = (uint32_t)cc;
	}

	/*
	 * We may have to do an extra subtraction, but only if the
	 * value in x[] is indeed greater than or equal to that of m[],
	 * which is why we must do two calls (first call computes the
	 * carry, second call performs the subtraction only if the carry
	 * is 0).
	 */
	br_i31_sub(x, m, NOT(br_i31_sub(x, m, 0)));
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static uint32_t br_i31_iszero(const uint32_t* x)
{
	uint32_t z;
	size_t u;

	z = 0;
	for (u = (x[0] + 31) >> 5; u > 0; u--) {
		z |= x[u];
	}
	return ~(z | -z) >> 31;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_modpow(uint32_t* x, const unsigned char* e, size_t elen,
	const uint32_t* m, uint32_t m0i, uint32_t* t1, uint32_t* t2)
{
	size_t mlen;
	uint32_t k;

	/*
	 * 'mlen' is the length of m[] expressed in bytes (including
	 * the "bit length" first field).
	 */
	mlen = ((m[0] + 63) >> 5) * sizeof m[0];

	/*
	 * Throughout the algorithm:
	 * -- t1[] is in Montgomery representation; it contains x, x^2,
	 * x^4, x^8...
	 * -- The result is accumulated, in normal representation, in
	 * the x[] array.
	 * -- t2[] is used as destination buffer for each multiplication.
	 *
	 * Note that there is no need to call br_i32_from_monty().
	 */
	memcpy(t1, x, mlen);
	br_i31_to_monty(t1, m);
	br_i31_zero(x, m[0]);
	x[1] = 1;
	for (k = 0; k < ((uint32_t)elen << 3); k++) {
		uint32_t ctl;

		ctl = (e[elen - 1 - (k >> 3)] >> (k & 7)) & 1;
		br_i31_montymul(t2, x, t1, m, m0i);
		CCOPY(ctl, x, t2, mlen);
		br_i31_montymul(t2, t1, t1, m, m0i);
		memcpy(t1, t2, mlen);
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_montymul(uint32_t* d, const uint32_t* x, const uint32_t* y,
	const uint32_t* m, uint32_t m0i)
{
	size_t len, len4, u, v;
	uint64_t dh;

	len = (m[0] + 31) >> 5;
	len4 = len & ~(size_t)3;
	br_i31_zero(d, m[0]);
	dh = 0;
	for (u = 0; u < len; u++) {
		uint32_t f, xu;
		uint64_t r, zh;

		xu = x[u + 1];
		f = MUL31_lo((d[1] + MUL31_lo(x[u + 1], y[1])), m0i);

		r = 0;
		for (v = 0; v < len4; v += 4) {
			uint64_t z;

			z = (uint64_t)d[v + 1] + MUL31(xu, y[v + 1])
				+ MUL31(f, m[v + 1]) + r;
			r = z >> 31;
			d[v + 0] = (uint32_t)z & 0x7FFFFFFF;
			z = (uint64_t)d[v + 2] + MUL31(xu, y[v + 2])
				+ MUL31(f, m[v + 2]) + r;
			r = z >> 31;
			d[v + 1] = (uint32_t)z & 0x7FFFFFFF;
			z = (uint64_t)d[v + 3] + MUL31(xu, y[v + 3])
				+ MUL31(f, m[v + 3]) + r;
			r = z >> 31;
			d[v + 2] = (uint32_t)z & 0x7FFFFFFF;
			z = (uint64_t)d[v + 4] + MUL31(xu, y[v + 4])
				+ MUL31(f, m[v + 4]) + r;
			r = z >> 31;
			d[v + 3] = (uint32_t)z & 0x7FFFFFFF;
		}
		for (; v < len; v++) {
			uint64_t z;

			z = (uint64_t)d[v + 1] + MUL31(xu, y[v + 1])
				+ MUL31(f, m[v + 1]) + r;
			r = z >> 31;
			d[v] = (uint32_t)z & 0x7FFFFFFF;
		}

		zh = dh + r;
		d[len] = (uint32_t)zh & 0x7FFFFFFF;
		dh = zh >> 31;
	}

	/*
	 * We must write back the bit length because it was overwritten in
	 * the loop (not overwriting it would require a test in the loop,
	 * which would yield bigger and slower code).
	 */
	d[0] = m[0];

	/*
	 * d[] may still be greater than m[] at that point; notably, the
	 * 'dh' word may be non-zero.
	 */
	br_i31_sub(d, m, NEQ((uint16_t)dh, 0) | NOT(br_i31_sub(d, m, 0)));
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/



 /* see inner.h */
static void br_i31_muladd_small(uint32_t* x, uint32_t z, const uint32_t* m)
{
	uint32_t m_bitlen;
	unsigned mblr;
	size_t u, mlen;
	uint32_t a0, a1, b0, hi, g, q, tb;
	uint32_t under, over;
	uint32_t cc;

	/*
	 * We can test on the modulus bit length since we accept to
	 * leak that length.
	 */
	m_bitlen = m[0];
	if (m_bitlen == 0) {
		return;
	}
	if (m_bitlen <= 31) {
		uint32_t lo;

		hi = x[1] >> 1;
		lo = (x[1] << 31) | z;
		x[1] = br_rem(hi, lo, m[1]);
		return;
	}
	mlen = (m_bitlen + 31) >> 5;
	mblr = (unsigned)m_bitlen & 31;

	/*
	 * Principle: we estimate the quotient (x*2^31+z)/m by
	 * doing a 64/32 division with the high words.
	 *
	 * Let:
	 *   w = 2^31
	 *   a = (w*a0 + a1) * w^N + a2
	 *   b = b0 * w^N + b2
	 * such that:
	 *   0 <= a0 < w
	 *   0 <= a1 < w
	 *   0 <= a2 < w^N
	 *   w/2 <= b0 < w
	 *   0 <= b2 < w^N
	 *   a < w*b
	 * I.e. the two top words of a are a0:a1, the top word of b is
	 * b0, we ensured that b0 is "full" (high bit set), and a is
	 * such that the quotient q = a/b fits on one word (0 <= q < w).
	 *
	 * If a = b*q + r (with 0 <= r < q), we can estimate q by
	 * doing an Euclidean division on the top words:
	 *   a0*w+a1 = b0*u + v  (with 0 <= v < b0)
	 * Then the following holds:
	 *   0 <= u <= w
	 *   u-2 <= q <= u
	 */
	hi = x[mlen];
	if (mblr == 0) {
		a0 = x[mlen];
		memmove(x + 2, x + 1, (mlen - 1) * sizeof * x);
		x[1] = z;
		a1 = x[mlen];
		b0 = m[mlen];
	}
	else {
		a0 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
		memmove(x + 2, x + 1, (mlen - 1) * sizeof * x);
		x[1] = z;
		a1 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
		b0 = ((m[mlen] << (31 - mblr)) | (m[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
	}

	/*
	 * We estimate a divisor q. If the quotient returned by br_div()
	 * is g:
	 * -- If a0 == b0 then g == 0; we want q = 0x7FFFFFFF.
	 * -- Otherwise:
	 *    -- if g == 0 then we set q = 0;
	 *    -- otherwise, we set q = g - 1.
	 * The properties described above then ensure that the true
	 * quotient is q-1, q or q+1.
	 *
	 * Take care that a0, a1 and b0 are 31-bit words, not 32-bit. We
	 * must adjust the parameters to br_div() accordingly.
	 */
	g = br_div(a0 >> 1, a1 | (a0 << 31), b0);
	q = MUX(EQ(a0, b0), 0x7FFFFFFF, MUX(EQ(g, 0), 0, g - 1));

	/*
	 * We subtract q*m from x (with the extra high word of value 'hi').
	 * Since q may be off by 1 (in either direction), we may have to
	 * add or subtract m afterwards.
	 *
	 * The 'tb' flag will be true (1) at the end of the loop if the
	 * result is greater than or equal to the modulus (not counting
	 * 'hi' or the carry).
	 */
	cc = 0;
	tb = 1;
	for (u = 1; u <= mlen; u++) {
		uint32_t mw, zw, xw, nxw;
		uint64_t zl;

		mw = m[u];
		zl = MUL31(mw, q) + cc;
		cc = (uint32_t)(zl >> 31);
		zw = (uint32_t)zl & (uint32_t)0x7FFFFFFF;
		xw = x[u];
		nxw = xw - zw;
		cc += nxw >> 31;
		nxw &= 0x7FFFFFFF;
		x[u] = nxw;
		tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
	}

	/*
	 * If we underestimated q, then either cc < hi (one extra bit
	 * beyond the top array word), or cc == hi and tb is true (no
	 * extra bit, but the result is not lower than the modulus). In
	 * these cases we must subtract m once.
	 *
	 * Otherwise, we may have overestimated, which will show as
	 * cc > hi (thus a negative result). Correction is adding m once.
	 */
	over = GT(cc, hi);
	under = ~over & (tb | LT(cc, hi));
	br_i31_add(x, m, over);
	br_i31_sub(x, m, under);
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static uint32_t br_i31_ninv31(uint32_t x)
{
	uint32_t y;

	y = 2 - x;
	y *= 2 - y * x;
	y *= 2 - y * x;
	y *= 2 - y * x;
	y *= 2 - y * x;
	return MUX(x & 1, -y, 0) & 0x7FFFFFFF;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static void br_i31_rshift(uint32_t* x, int count)
{
	size_t u, len;
	uint32_t r;

	len = (x[0] + 31) >> 5;
	if (len == 0) {
		return;
	}
	r = x[1] >> count;
	for (u = 2; u <= len; u++) {
		uint32_t w;

		w = x[u];
		x[u - 1] = ((w << (31 - count)) | r) & 0x7FFFFFFF;
		r = w >> count;
	}
	x[len] = r;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


 /* see inner.h */
static uint32_t br_i31_sub(uint32_t* a, const uint32_t* b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 63) >> 5;
	for (u = 1; u < m; u++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw - bw - cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & 0x7FFFFFFF, aw);
	}
	return cc;
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/

 /* see inner.h */
static void br_i31_to_monty(uint32_t* x, const uint32_t* m)
{
	uint32_t k;

	for (k = (m[0] + 31) >> 5; k > 0; k--) {
		br_i31_muladd_small(x, 0, m);
	}
}


/*======================================================================================================================================*/
/*======================================================================================================================================*/


#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((Y) & (Z)) | (((Y) | (Z)) & (X)))

#define ROTR(x, n)    (((uint32_t)(x) << (32 - (n))) | ((uint32_t)(x) >> (n)))

#define BSG2_0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSG2_1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSG2_0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ (uint32_t)((x) >> 3))
#define SSG2_1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ (uint32_t)((x) >> 10))

 /* see inner.h */
const uint32_t br_sha224_IV[8] = {
	0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
	0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

/* see inner.h */
const uint32_t br_sha256_IV[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint32_t K[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

/* see inner.h */
static void br_sha2small_round(const unsigned char* buf, uint32_t* val)
{

#define SHA2_STEP(A, B, C, D, E, F, G, H, j)   do { \
		uint32_t T1, T2; \
		T1 = H + BSG2_1(E) + CH(E, F, G) + K[j] + w[j]; \
		T2 = BSG2_0(A) + MAJ(A, B, C); \
		D += T1; \
		H = T1 + T2; \
	} while (0)

	int i;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t w[64];

	br_range_dec32be(w, 16, buf);
	for (i = 16; i < 64; i++) {
		w[i] = SSG2_1(w[i - 2]) + w[i - 7]
			+ SSG2_0(w[i - 15]) + w[i - 16];
	}
	a = val[0];
	b = val[1];
	c = val[2];
	d = val[3];
	e = val[4];
	f = val[5];
	g = val[6];
	h = val[7];
	for (i = 0; i < 64; i += 8) {
		SHA2_STEP(a, b, c, d, e, f, g, h, i + 0);
		SHA2_STEP(h, a, b, c, d, e, f, g, i + 1);
		SHA2_STEP(g, h, a, b, c, d, e, f, i + 2);
		SHA2_STEP(f, g, h, a, b, c, d, e, i + 3);
		SHA2_STEP(e, f, g, h, a, b, c, d, i + 4);
		SHA2_STEP(d, e, f, g, h, a, b, c, i + 5);
		SHA2_STEP(c, d, e, f, g, h, a, b, i + 6);
		SHA2_STEP(b, c, d, e, f, g, h, a, i + 7);
	}
	val[0] += a;
	val[1] += b;
	val[2] += c;
	val[3] += d;
	val[4] += e;
	val[5] += f;
	val[6] += g;
	val[7] += h;
}

static void sha2small_update(br_sha224_context* cc, const void* data, size_t len)
{
	const unsigned char* buf;
	size_t ptr;

	buf = (unsigned char*)data;
	ptr = (size_t)cc->count & 63;
	cc->count += (uint64_t)len;
	while (len > 0) {
		size_t clen;

		clen = 64 - ptr;
		if (clen > len) {
			clen = len;
		}
		memcpy(cc->buf + ptr, buf, clen);
		ptr += clen;
		buf += clen;
		len -= clen;
		if (ptr == 64) {
			br_sha2small_round(cc->buf, cc->val);
			ptr = 0;
		}
	}
}

static void sha2small_out(const br_sha224_context* cc, void* dst, int num)
{
	unsigned char buf[64];
	uint32_t val[8];
	size_t ptr;

	ptr = (size_t)cc->count & 63;
	memcpy(buf, cc->buf, ptr);
	memcpy(val, cc->val, sizeof val);
	buf[ptr++] = 0x80;
	if (ptr > 56) {
		memset(buf + ptr, 0, 64 - ptr);
		br_sha2small_round(buf, val);
		memset(buf, 0, 56);
	}
	else {
		memset(buf + ptr, 0, 56 - ptr);
	}
	br_enc64be(buf + 56, cc->count << 3);
	br_sha2small_round(buf, val);
	br_range_enc32be(dst, val, num);
}

/* see bearssl.h */
static void br_sha224_init(br_sha224_context* cc)
{
	cc->vtable = &br_sha224_vtable;
	memcpy(cc->val, br_sha224_IV, sizeof cc->val);
	cc->count = 0;
}

/* see bearssl.h */
static void br_sha224_update(br_sha224_context* cc, const void* data, size_t len)
{
	sha2small_update(cc, data, len);
}

/* see bearssl.h */
static void br_sha224_out(const br_sha224_context* cc, void* dst)
{
	sha2small_out(cc, dst, 7);
}

/* see bearssl.h */
static uint64_t br_sha224_state(const br_sha224_context* cc, void* dst)
{
	br_range_enc32be(dst, cc->val, 8);
	return cc->count;
}

/* see bearssl.h */
static void br_sha224_set_state(br_sha224_context* cc, const void* stb, uint64_t count)
{
	br_range_dec32be(cc->val, 8, stb);
	cc->count = count;
}

/* see bearssl.h */
static void br_sha256_init(br_sha256_context* cc)
{
	cc->vtable = &br_sha256_vtable;
	memcpy(cc->val, br_sha256_IV, sizeof cc->val);
	cc->count = 0;
}

/* see bearssl.h */
static void br_sha256_out(const br_sha256_context* cc, void* dst)
{
	sha2small_out(cc, dst, 8);
}

/* see bearssl.h */
const br_hash_class br_sha224_vtable = {
	sizeof(br_sha224_context),
	BR_HASHDESC_ID(br_sha224_ID)
		| BR_HASHDESC_OUT(28)
		| BR_HASHDESC_STATE(32)
		| BR_HASHDESC_LBLEN(6)
		| BR_HASHDESC_MD_PADDING
		| BR_HASHDESC_MD_PADDING_BE,
	(void (*)(const br_hash_class**)) & br_sha224_init,
	(void (*)(const br_hash_class**,
		const void*, size_t)) & br_sha224_update,
	(void (*)(const br_hash_class* const*, void*)) & br_sha224_out,
	(uint64_t(*)(const br_hash_class* const*, void*)) & br_sha224_state,
	(void (*)(const br_hash_class**, const void*, uint64_t))
		& br_sha224_set_state
};

/* see bearssl.h */
const br_hash_class br_sha256_vtable = {
	sizeof(br_sha256_context),
	BR_HASHDESC_ID(br_sha256_ID)
		| BR_HASHDESC_OUT(32)
		| BR_HASHDESC_STATE(32)
		| BR_HASHDESC_LBLEN(6)
		| BR_HASHDESC_MD_PADDING
		| BR_HASHDESC_MD_PADDING_BE,
	(void (*)(const br_hash_class**)) & br_sha256_init,
	(void (*)(const br_hash_class**,
		const void*, size_t)) & br_sha256_update,
	(void (*)(const br_hash_class* const*, void*)) & br_sha256_out,
	(uint64_t(*)(const br_hash_class* const*, void*)) & br_sha256_state,
	(void (*)(const br_hash_class**, const void*, uint64_t))
		& br_sha256_set_state
};

const br_ec_curve_def br_secp256r1 = {
	BR_EC_secp256r1,
	P256_N, sizeof P256_N,
	P256_G, sizeof P256_G
};



/**********************************************************************************************************************************/
/*                                                the Main Verification Function                                                  */
/**********************************************************************************************************************************/

p256_ret_t p256_verify(uint8_t* msg, size_t msg_len, uint8_t* sig, const uint8_t* pk)
{
	unsigned char hash[64];
	size_t hash_len = 32; // SHA-256
	br_hash_compat_context hc;
	const br_hash_class* hf = &br_sha256_vtable;
	br_ecdsa_vrfy vrfy = &br_ecdsa_i31_vrfy_raw;

	hf->init(&hc.vtable);
	hf->update(&hc.vtable, msg, msg_len);
	hf->out(&hc.vtable, hash);

	size_t sig_len = 64; // P-256

	// TODO: p256_verify should take a pk_len argument so that we can verify
	// here the following precondition:
	// pk must be at least 65 bytes long, or 33 if the first byte is 0x02 or 0x03.

	unsigned char public_key[65];
	if ((pk[0] != 0x04) && (pk[0] != 0x02) && (pk[0] != 0x03)) {
		return P256_INVALID_SIGNATURE; // TODO: more specific errors
	}

	size_t pk_len = (pk[0] == 0x04) ? 65 : 33;
	memcpy(public_key, pk, pk_len);

	const br_ec_public_key pub = { BR_EC_secp256r1, public_key , pk_len };


	if (vrfy(&br_ec_p256_m31, hash, hash_len,
		&pub, sig, sig_len) != 1)
	{
		return P256_INVALID_SIGNATURE;
	}

	return P256_SUCCESS;
}
