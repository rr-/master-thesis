#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "common.h"

/* md5 stuff */

const uint32_t md5_iv[4] =
{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
};

const uint32_t md5_shift[64] =
{
	/* round 1 */
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	/* round 2 */
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	/* round 3 */
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	/* round 4 */
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
};

const uint32_t md5_msg_index[64] =
{
	/* round 1 */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	/* round 2 */ 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	/* round 3 */ 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	/* round 4 */ 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
};

const uint32_t md5_add[64] =
{
	/* round 1 */
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	/* round 2 */
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	/* round 3 */
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	/* round 4 */
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z)
{
	return z^(x&(y^z));
}

uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z)
{
	return y^(z&(x^y));
}

uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}

uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z)
{
	return y^(x|~z);
}



/* message delta as in wang's paper */
const uint32_t message_delta[16] =
{
	/* 0 */ 0,
	/* 1 */ 0,
	/* 2 */ 0,
	/* 3 */ 0,
	/* 4 */ 0x80000000,
	/* 5 */ 0,
	/* 6 */ 0,
	/* 7 */ 0,
	/* 8 */ 0,
	/* 9 */ 0,
	/* 10 */ 0,
	/* 11 */ 0x00008000,
	/* 12 */ 0,
	/* 13 */ 0,
	/* 14 */ 0x80000000,
	/* 15 */ 0,
};

const uint32_t differences[64] =
{
	/* a1 */ 0x7e000000,
	/* d1 */ 0x7dffffe0,
	/* c1 */ 0x7dfef7e0,
	/* b1 */ 0x7dffffe2,
	/* a2 */ 0x7ffffcbf,
	/* d2 */ 0x80110000,
	/* c2 */ 0x88000040,
	/* b2 */ 0x80818000,
	/* a3 */ 0x7fffffbf,
	/* d3 */ 0x7ffff000,
	/* c3 */ 1 << 31,
	/* b3 */ 0x80002080,
	/* a4 */ 0x7f000000,
	/* d4 */ 1 << 31,
	/* c4 */ 0x7fff7ff8,
	/* b4 */ 0xa0000000,
	/* a5 */ 1 << 31,
	/* d5 */ 1 << 31,
	/* c5 */ 0x7ffe0000,
	/* b5 */ 1 << 31,
	/* a6 */ 1 << 31,
	/* d6 */ 1 << 31,
	/* c6 */ 0,
	/* b6 */ 0,
	/* a7 */ 0,
	/* d7 */ 0,
	/* c7 */ 0,
	/* b7 */ 0,
	/* a8 */ 0,
	/* d8 */ 0,
	/* c8 */ 0,
	/* b8 */ 0,
	/* a9 */ 0,
	/* d9 */ 0,
	/* c9 */ 1 << 31,
	/* b9 */ 1 << 31,
	/* a10 */ 1 << 31,
	/* d10 */ 1 << 31,
	/* c10 */ 1 << 31,
	/* b10 */ 1 << 31,
	/* a11 */ 1 << 31,
	/* d11 */ 1 << 31,
	/* c11 */ 1 << 31,
	/* b11 */ 1 << 31,
	/* a12 */ 1 << 31,
	/* d12 */ 1 << 31,
	/* c12 */ 1 << 31,
	/* b12 */ 1 << 31,
	/* a13 */ 1 << 31,
	/* d13 */ 1 << 31,
	/* c13 */ 1 << 31,
	/* b13 */ 1 << 31,
	/* a14 */ 1 << 31,
	/* d14 */ 1 << 31,
	/* c14 */ 1 << 31,
	/* b14 */ 1 << 31,
	/* a15 */ 1 << 31,
	/* d15 */ 1 << 31,
	/* c15 */ 1 << 31,
	/* b15 */ 1 << 31,
	/* a16 */ 1 << 31,
	/* d16 */ 0,
	/* c16 */ 0,
	/* b16 */ 0,
};

const uint32_t sc_zero[64] =
{
	/* a1 */ 0x0a000820,
	/* d1 */ 0x02208026 | 0x701f10c0,
	/* c1 */ 0x40201080 | 0x00000018,
	/* b1 */ 0x443b19ee | 0x00000601,
	/* a2 */ 0xb41011af,
	/* d2 */ 0x9a1113a9,
	/* c2 */ 0x083201c0 | 0x01808000,
	/* b2 */ 0x1b810001 | 0x00000002,
	/* a3 */ 0x03828202 | 0x00001000,
	/* d3 */ 0x00041003,
	/* c3 */ 0x00021000 | 0x00086000,
	/* b3 */ 0x0007e000 | 0x7f000000,
	/* a4 */ 0x80000080,
	/* d4 */ 0xbf040000,
	/* c4 */ 0x82008008,
	/* b4 */ 0,
	/* a5 */ 0,
	/* d5 */ 0,
	/* c5 */ 0x80020000,
	/* b5 */ 0x80000000,
	/* a6 */ 0,
	/* d6 */ 0x80000000,
	/* c6 */ 0x80000000,
};

const uint32_t sc_one[64] =
{
	/* a1 */ 0x84200000,
	/* d1 */ 0x8c000800,
	/* c1 */ 0xbe1f0966,
	/* b1 */ 0xba040010,
	/* a2 */ 0x482f0e50,
	/* d2 */ 0x04220c56,
	/* c2 */ 0x96011e01,
	/* b2 */ 0x843283c0,
	/* a3 */ 0x9c0101c1,
	/* d3 */ 0x878383c0,
	/* c3 */ 0x800583c3,
	/* b3 */ 0x80081080,
	/* a4 */ 0x3f0fe008,
	/* d4 */ 0x400be088,
	/* c4 */ 0x7d000000,
	/* b4 */ 0x00000000,
	/* a5 */ 0,
	/* d5 */ 0,
	/* c5 */ 0,
	/* b5 */ 0,
};

const uint32_t sc_prev[64] =
{
	/* a1 */ 0x00000000,
	/* d1 */ 0x701f10c0,
	/* c1 */ 0x00000018,
	/* b1 */ 0x00000601,
	/* a2 */ 0x00000000,
	/* d2 */ 0x00000000,
	/* c2 */ 0x01808000,
	/* b2 */ 0x00000002,
	/* a3 */ 0x00001000,
	/* d3 */ 0x00000000,
	/* c3 */ 0x00086000,
	/* b3 */ 0x7f000000,
	/* a4 */ 0x00000000,
	/* d4 */ 0x00000000,
	/* c4 */ 0x00000000,
	/* b4 */ 0x00000000,
	/* a5 */ 0,
	/* d5 */ 0,
	/* c5 */ 0,
	/* b5 */ 0,
	/* a6 */ 0x80020000,
	/* d6 */ 0,
	/* c6 */ 0,
	/* b6 */ 0,
};

uint32_t randoms[32];
uint32_t myrandom(size_t index)
{
	return randoms[index];
}

bool check_sc(uint32_t *state1, uint32_t *state2, size_t i)
{
	if ((state1[i] & sc_prev[i - 1]) != (state1[i - 1] & sc_prev[i - 1]))
		return false;

	if ((state1[i] & sc_one[i - 1]) != sc_one[i - 1])
		return false;

	if (state1[i] & sc_zero[i - 1])
		return false;

	if ((state1[i] - state2[i]) != differences[i - 1])
		return false;

	return true;
}

void block1(
	uint32_t *msg1,
	uint32_t *msg2,
	uint32_t *state1,
	uint32_t *state2)
{
	bool ok;
	size_t i;
	size_t attempts = 0;

	while (true)
	{
		ok = true;

		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (1) %d\n", attempts);

		/* C1 */
		state1[3] = myrandom(0) & ~0x00800040;
		state2[3] = state1[3];

		/* B1 */
		state1[4] = (myrandom(1) | 0x80080800) & ~(0x00800040 | 0x0077f780);
		state1[4] |= (state1[3] & 0x0077f780);
		state2[4] = state1[4];

		/* A2 */
		state1[5] = (myrandom(2) | 0x88400025) & ~0x02bfffc0;
		state2[5] = state1[5] - 0x00000040;

		/* D2 */
		state1[6] = (myrandom(3) | 0x027fbc41) & ~(0x888043a4 | 0x7500001a);
		state1[6] |= (state1[5] & 0x7500001a);
		state2[6] = state1[6] - 0x7f800040;

		/* C2 */
		state1[7] = (myrandom(4) | 0x03fef820) & ~0xfc0107df;
		state2[7] = state1[7] - 0x07800041;

		/* B2 */
		state1[8] = (myrandom(5) | 0x01910540) & ~0xfe0eaabf;
		state2[8] = state1[8] - 0x00827fff;

		/* A3 */
		state1[9] = (myrandom(6) | 0xfb102f3d) & ~(0x040f80c2 | 0x00001000);
		state1[9] |= (state1[8] & 0x00001000);
		state2[9] = state1[9] - 0x8000003f;

		/* D3 */
		state1[10] = (myrandom(7) | 0x401f9040) & ~0x80802183;
		state2[10] = state1[10] - 0x7ffff000;

		/* C3 */
		state1[11] = (myrandom(8) | 0x000180c2) & ~(0xc00e3101 | 0x00004000);
		state1[11] |= (state1[10] & 0x00004000);
		state2[11] = state1[11] - 0x40000000;

		/* B3 */
		state1[12] = (myrandom(9) | 0x00081100) & ~(0xc007e080 | 0x03000000);
		state1[12] |= (state1[11] & 0x03000000);
		state2[12] = state1[12] - 0x80002080;

		/* A4 */
		state1[13] = (myrandom(10) | 0x410fe008) & ~0x82000180;
		state2[13] = state1[13] - 0x7f000000;

		/* D4 */
		state1[14] = (myrandom(11) | 0x000be188) & ~0xa3040000;
		state2[14] = state1[14] - 0x80000000;

		/* C4 */
		state1[15] = (myrandom(12) | 0x21008000) & ~0x82000008;
		state2[15] = state1[15] - 0x80007ff8;

		/* B4 */
		state1[16] = (myrandom(13) | 0x20000000) & ~0x80000000;
		state2[16] = state1[16] - 0xa0000000;

		/* A5 */
		state1[17] = myrandom(14) & ~(0x80020000 | 0x00008008);
		state1[17] |= (state1[16] & 0x00008008);
		state2[17] = state1[17] - 0x80000000;

		for (i = 6; i < 16; i ++)
		{
			msg1[i] = rot_right(state1[i + 1] - state1[i], md5_shift[i]) - md5_f(state1[i], state1[i - 1], state1[i - 2]) - state1[i - 3] - md5_add[i];
			msg2[i] = rot_right(state2[i + 1] - state2[i], md5_shift[i]) - md5_f(state2[i], state2[i - 1], state2[i - 2]) - state2[i - 3] - md5_add[i];
			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* D5 */
		state1[18] = rot_left(md5_g(state1[17], state1[16], state1[15]) + state1[14] + msg1[6] + md5_add[17], 9) + state1[17];
		state2[18] = rot_left(md5_g(state2[17], state2[16], state2[15]) + state2[14] + msg2[6] + md5_add[17], 9) + state2[17];
		if ((state1[18] & 0xa0020000) != (0x00020000 | (state1[17] & 0x20000000)))
			continue;
		if ((state1[18] ^ state2[18]) != 0x80000000)
			continue;

		/* C5 */
		state1[19] = rot_left(md5_g(state1[18], state1[17], state1[16]) + state1[15] + msg1[11] + md5_add[18], 14) + state1[18];
		state2[19] = rot_left(md5_g(state2[18], state2[17], state2[16]) + state2[15] + msg2[11] + md5_add[18], 14) + state2[18];
		if (state1[19] & 0x80020000)
			continue;
		if (state1[19] - state2[19] != 0x7ffe0000)
			continue;

		/* B5 */
		state1[20] = myrandom(15);
		state2[20] = state1[20] - 0x80000000;

		state1[1] = rot_left(md5_f(state1[0], state1[-1], state1[-2]) + state1[-3] + msg1[0] + md5_add[0], 7) + state1[0];
		state2[1] = state1[1];

		state1[2] = rot_left(md5_f(state1[1], state1[0], state1[-1]) + state1[-2] + msg1[1] + md5_add[1], 12) + state1[1];
		state2[2] = state1[2];

		msg1[0] = rot_right(state1[20] - state1[19], 20) - md5_g(state1[19], state1[18], state1[17]) - state1[16] - md5_add[19];
		msg2[0] = rot_right(state2[20] - state2[19], 20) - md5_g(state2[19], state2[18], state2[17]) - state2[16] - md5_add[19];
		if ((msg1[0] ^ msg2[0]) != message_delta[0])
			continue;

		msg1[1] = rot_right(state1[17] - state1[16], md5_shift[16]) - md5_g(state1[16], state1[15], state1[14]) - state1[13] - md5_add[16];
		msg2[1] = rot_right(state2[17] - state2[16], md5_shift[16]) - md5_g(state2[16], state2[15], state2[14]) - state2[13] - md5_add[16];
		if ((msg1[1] ^ msg2[1]) != message_delta[1])
			continue;

		for (i = 2; i < 6; i ++)
		{
			msg1[i] = rot_right(state1[i + 1] - state1[i], md5_shift[i]) - md5_f(state1[i], state1[i - 1], state1[i - 2]) - state1[i - 3] - md5_add[i];
			msg2[i] = rot_right(state2[i + 1] - state2[i], md5_shift[i]) - md5_f(state2[i], state2[i - 1], state2[i - 2]) - state2[i - 3] - md5_add[i];
			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A6 to B8 */
		for (i = 21; i <= 32; i ++)
		{
			state1[i] = rot_left(md5_g(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_g(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A9 to C12 */
		for (i = 33; i <= 47; i ++)
		{
			state1[i] = rot_left(md5_h(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_h(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* B12 */
		state1[48] = rot_left(md5_h(state1[47], state1[46], state1[45]) + state1[44] + msg1[md5_msg_index[47]] + md5_add[47], 23) + state1[47];
		state2[48] = rot_left(md5_h(state2[47], state2[46], state2[45]) + state2[44] + msg2[md5_msg_index[47]] + md5_add[47], 23) + state2[47];
		if ((state1[48] ^ state1[46]) & 0x80000000)
			continue;
		if ((state1[48] ^ state2[48]) != 0x80000000)
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[md5_msg_index[48]] + md5_add[48], 6) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[md5_msg_index[48]] + md5_add[48], 6) + state2[48];
		if ((state1[49] ^ state1[47]) & 0x80000000)
			continue;
		if ((state1[49] ^ state2[49]) != 0x80000000)
			continue;

		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[md5_msg_index[49]] + md5_add[49], 10) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[md5_msg_index[49]] + md5_add[49], 10) + state2[49];
		if (!((state1[50] ^ state1[48]) & 0x80000000))
			continue;
		if ((state1[50] ^ state2[50]) != 0x80000000)
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[md5_msg_index[50]] + md5_add[50], 15) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[md5_msg_index[50]] + md5_add[50], 15) + state2[50];
		if ((state1[51] ^ state1[49]) & 0x80000000)
			continue;
		if ((state1[51] ^ state2[51]) != 0x80000000)
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[md5_msg_index[51]] + md5_add[51], 21) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[md5_msg_index[51]] + md5_add[51], 21) + state2[51];
		if ((state1[52] ^ state1[50]) & 0x80000000)
			continue;
		if ((state1[52] ^ state2[52]) != 0x80000000)
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[md5_msg_index[52]] + md5_add[52], 6) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[md5_msg_index[52]] + md5_add[52], 6) + state2[52];
		if ((state1[53] ^ state1[51]) & 0x80000000)
			continue;
		if ((state1[53] ^ state2[53]) != 0x80000000)
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[md5_msg_index[53]] + md5_add[53], 10) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[md5_msg_index[53]] + md5_add[53], 10) + state2[53];
		if ((state1[54] ^ state1[52]) & 0x80000000)
			continue;
		if ((state1[54] ^ state2[54]) != 0x80000000)
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[md5_msg_index[54]] + md5_add[54], 15) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[md5_msg_index[54]] + md5_add[54], 15) + state2[54];
		if ((state1[55] ^ state1[53]) & 0x80000000)
			continue;
		if ((state1[55] ^ state2[55]) != 0x80000000)
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[md5_msg_index[55]] + md5_add[55], 21) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[md5_msg_index[55]] + md5_add[55], 21) + state2[55];
		if ((state1[56] ^ state1[54]) & 0x80000000)
			continue;
		if ((state1[56] ^ state2[56]) != 0x80000000)
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[md5_msg_index[56]] + md5_add[56], 6) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[md5_msg_index[56]] + md5_add[56], 6) + state2[56];
		if ((state1[57] ^ state1[55]) & 0x80000000)
			continue;
		if ((state1[57] ^ state2[57]) != 0x80000000)
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[md5_msg_index[57]] + md5_add[57], 10) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[md5_msg_index[57]] + md5_add[57], 10) + state2[57];
		if ((state1[58] ^ state1[56]) & 0x80000000)
			continue;
		if ((state1[58] ^ state2[58]) != 0x80000000)
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[md5_msg_index[58]] + md5_add[58], 15) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[md5_msg_index[58]] + md5_add[58], 15) + state2[58];
		if ((state1[59] ^ state1[57]) & 0x80000000)
			continue;
		if ((state1[59] ^ state2[59]) != 0x80000000)
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[md5_msg_index[59]] + md5_add[59], 21) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[md5_msg_index[59]] + md5_add[59], 21) + state2[59];
		if (state1[60] & 0x02000000)
			continue;
		if ((state1[60] ^ state2[60]) != 0x80000000)
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[md5_msg_index[60]] + md5_add[60], 6) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[md5_msg_index[60]] + md5_add[60], 6) + state2[60];
		if ((state1[61] ^ state2[61]) != 0x80000000)
			continue;

		/* D16 */
		state1[62] = rot_left(md5_i(state1[61], state1[60], state1[59]) + state1[58] + msg1[md5_msg_index[61]] + md5_add[61], 10) + state1[61];
		state2[62] = rot_left(md5_i(state2[61], state2[60], state2[59]) + state2[58] + msg2[md5_msg_index[61]] + md5_add[61], 10) + state2[61];
		if (state1[62] & 0x02000000)
			continue;
		if ((state1[62] - state2[62]) != 0x7e000000)
			continue;

		/* C16 */
		state1[63] = rot_left(md5_i(state1[62], state1[61], state1[60]) + state1[59] + msg1[md5_msg_index[62]] + md5_add[62], 15) + state1[62];
		state2[63] = rot_left(md5_i(state2[62], state2[61], state2[60]) + state2[59] + msg2[md5_msg_index[62]] + md5_add[62], 15) + state2[62];
		if (((state1[63] + md5_iv[2]) & 0x86000000) != (((state1[62] + md5_iv[3]) & 0x80000000) | 0x02000000))
			continue;
		if ((state1[63] - state2[63]) != 0x7e000000)
			continue;

		/* B16 */
		state1[64] = rot_left(md5_i(state1[63], state1[62], state1[61]) + state1[60] + msg1[md5_msg_index[63]] + md5_add[63], 21) + state1[63];
		state2[64] = rot_left(md5_i(state2[63], state2[62], state2[61]) + state2[60] + msg2[md5_msg_index[63]] + md5_add[63], 21) + state2[63];
		if (((state1[64] + md5_iv[1]) & 0x86000020) != ((state1[63] + md5_iv[2]) & 0x80000000))
			continue;
		if ((state1[64] - state2[64]) != 0x7e000000)
			continue;

		return;
	}
}

void block2(
	uint32_t *msg1,
	uint32_t *msg2,
	uint32_t *state1,
	uint32_t *state2)
{
	size_t i;
	size_t attempts = 0;
	bool ok;

	while (true)
	{
		ok = true;
		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (2) %d\n", attempts);

		for (i = 0; i < 16; i ++)
		{
			state1[i + 1] = (myrandom(i + 16) | sc_one[i]) & ~sc_zero[i];
			state1[i + 1] |= (state1[i] & sc_prev[i]);
			state2[i + 1] = state1[i + 1] - differences[i];
		}

		for (i = 0; i < 16; i ++)
		{
			msg1[16 + i] = rot_right(state1[i + 1] - state1[i], md5_shift[i]) - md5_f(state1[i], state1[i - 1], state1[i - 2]) - state1[i - 3] - md5_add[i];
			msg2[16 + i] = rot_right(state2[i + 1] - state2[i], md5_shift[i]) - md5_f(state2[i], state2[i - 1], state2[i - 2]) - state2[i - 3] - md5_add[i];
			if ((msg1[16 + i] ^ msg2[16 + i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A5 */
		state1[17] = rot_left(md5_g(state1[16], state1[15], state1[14]) + state1[13] + msg1[17] + md5_add[16], md5_shift[16]) + state1[16];
		state2[17] = rot_left(md5_g(state2[16], state2[15], state2[14]) + state2[13] + msg2[17] + md5_add[16], md5_shift[16]) + state2[16];
		if ((state1[17] & 0x80028008) != (state1[16] & 0x00008008))
			continue;
		if ((state1[17] ^ state2[17]) != differences[16])
			continue;

		/* D5 */
		state1[18] = rot_left(md5_g(state1[17], state1[16], state1[15]) + state1[14] + msg1[22] + md5_add[17], md5_shift[17]) + state1[17];
		state2[18] = rot_left(md5_g(state2[17], state2[16], state2[15]) + state2[14] + msg2[22] + md5_add[17], md5_shift[17]) + state2[17];
		if ((state1[18] & 0xa0020000) != ((state1[17] & 0x20000000) | 0x00020000))
			continue;
		if ((state1[18] ^ state2[18]) != differences[17])
			continue;

		/* C5 to B8 */
		for (i = 19; i <= 32; i ++)
		{
			state1[i] = rot_left(md5_g(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_g(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A9 to C12 */
		for (i = 33; i <= 47; i ++)
		{
			state1[i] = rot_left(md5_h(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_h(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* B12 */
		state1[48] = rot_left(md5_h(state1[47], state1[46], state1[45]) + state1[44] + msg1[18] + md5_add[47], md5_shift[47]) + state1[47];
		state2[48] = rot_left(md5_h(state2[47], state2[46], state2[45]) + state2[44] + msg2[18] + md5_add[47], md5_shift[47]) + state2[47];
		if ((state1[48] & 0x80000000) != (state1[46] & 0x80000000))
			continue;
		if ((state1[48] ^ state2[48]) != differences[47])
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[16] + md5_add[48], md5_shift[48]) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[16] + md5_add[48], md5_shift[48]) + state2[48];
		if ((state1[49] & 0x80000000) != (state1[47] & 0x80000000))
			continue;
		if ((state1[49] ^ state2[49]) != differences[48])
			continue;

		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[23] + md5_add[49], md5_shift[49]) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[23] + md5_add[49], md5_shift[49]) + state2[49];
		if ((state1[50] ^ state2[50]) != differences[49])
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[30] + md5_add[50], md5_shift[50]) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[30] + md5_add[50], md5_shift[50]) + state2[50];
		if ((state1[51] & 0x80000000) != (state1[49] & 0x80000000))
			continue;
		if ((state1[51] ^ state2[51]) != differences[50])
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[21] + md5_add[51], md5_shift[51]) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[21] + md5_add[51], md5_shift[51]) + state2[51];
		if ((state1[52] & 0x80000000) != (state1[50] & 0x80000000))
			continue;
		if ((state1[52] ^ state2[52]) != differences[51])
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[28] + md5_add[52], md5_shift[52]) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[28] + md5_add[52], md5_shift[52]) + state2[52];
		if ((state1[53] & 0x80000000) != (state1[51] & 0x80000000))
			continue;
		if ((state1[53] ^ state2[53]) != differences[52])
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[19] + md5_add[53], md5_shift[53]) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[19] + md5_add[53], md5_shift[53]) + state2[53];
		if ((state1[54] & 0x80000000) != (state1[52] & 0x80000000))
			continue;
		if ((state1[54] ^ state2[54]) != differences[53])
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[26] + md5_add[54], md5_shift[54]) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[26] + md5_add[54], md5_shift[54]) + state2[54];
		if ((state1[55] & 0x80000000) != (state1[53] & 0x80000000))
			continue;
		if ((state1[55] ^ state2[55]) != differences[54])
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[17] + md5_add[55], md5_shift[55]) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[17] + md5_add[55], md5_shift[55]) + state2[55];
		if ((state1[56] & 0x80000000) != (state1[54] & 0x80000000))
			continue;
		if ((state1[56] ^ state2[56]) != differences[55])
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[24] + md5_add[56], md5_shift[56]) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[24] + md5_add[56], md5_shift[56]) + state2[56];
		if ((state1[57] & 0x80000000) != (state1[55] & 0x80000000))
			continue;
		if ((state1[57] ^ state2[57]) != differences[56])
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[31] + md5_add[57], md5_shift[57]) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[31] + md5_add[57], md5_shift[57]) + state2[57];
		if ((state1[58] & 0x80000000) != (state1[56] & 0x80000000))
			continue;
		if ((state1[58] ^ state2[58]) != differences[57])
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[22] + md5_add[58], md5_shift[58]) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[22] + md5_add[58], md5_shift[58]) + state2[58];
		if ((state1[59] & 0x80000000) != (state1[57] & 0x80000000))
			continue;
		if ((state1[59] ^ state2[59]) != differences[58])
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[29] + md5_add[59], md5_shift[59]) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[29] + md5_add[59], md5_shift[59]) + state2[59];
		if ((state1[60] ^ state2[60]) != differences[59])
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[20] + md5_add[60], md5_shift[60]) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[20] + md5_add[60], md5_shift[60]) + state2[60];
		if ((state1[61] ^ state2[61]) != differences[60])
			continue;
		if ((state1[-3] + state1[61]) != (state2[-3] + state2[61]))
			continue;

		/* D16 */
		state1[62] = rot_left(md5_i(state1[61], state1[60], state1[59]) + state1[58] + msg1[27] + md5_add[61], md5_shift[61]) + state1[61];
		state2[62] = rot_left(md5_i(state2[61], state2[60], state2[59]) + state2[58] + msg2[27] + md5_add[61], md5_shift[61]) + state2[61];
		if ((state1[-2] + state1[62]) != (state2[-2] + state2[62]))
			continue;

		/* C16 */
		state1[63] = rot_left(md5_i(state1[62], state1[61], state1[60]) + state1[59] + msg1[18] + md5_add[62], md5_shift[62]) + state1[62];
		state2[63] = rot_left(md5_i(state2[62], state2[61], state2[60]) + state2[59] + msg2[18] + md5_add[62], md5_shift[62]) + state2[62];
		if ((state1[-1] + state1[63]) != (state2[-1] + state2[63]))
			continue;

		/* B16 */
		state1[64] = rot_left(md5_i(state1[63], state1[62], state1[61]) + state1[60] + msg1[25] + md5_add[63], md5_shift[63]) + state1[63];
		state2[64] = rot_left(md5_i(state2[63], state2[62], state2[61]) + state2[60] + msg2[25] + md5_add[63], md5_shift[63]) + state2[63];
		if ((state1[0] + state1[64]) != (state2[0] + state2[64]))
			continue;

		return;
	}
}

void gen_collisions(uint32_t msg1[32], uint32_t msg2[32])
{
	uint32_t state1real[65+4], state2real[65+4];
	uint32_t *state1, *state2;

	state1 = state1real+4;
	state2 = state2real+4;
	state1[-3] = state2[-3] = md5_iv[0];
	state1[-2] = state2[-2] = md5_iv[3];
	state1[-1] = state2[-1] = md5_iv[2];
	state1[0] = state2[0] = md5_iv[1];

	block1(msg1, msg2, state1, state2);

	state1[-3] += state1[61];
	state1[-2] += state1[62];
	state1[-1] += state1[63];
	state1[0] += state1[64];

	state2[-3] += state2[61];
	state2[-2] += state2[62];
	state2[-1] += state2[63];
	state2[0] += state2[64];

	block2(msg1, msg2, state1, state2);
}

int main(int argc, char *argv[])
{
	size_t i;
	uint32_t msg1[32], msg2[32];

	randoms[0] = 0x272041c9;
	randoms[1] = 0x36d69572;
	randoms[2] = 0x0967f364;
	randoms[3] = 0x471aad20;
	randoms[4] = 0x58b34b54;
	randoms[5] = 0x2cad4fe2;
	randoms[6] = 0x57085139;
	randoms[7] = 0x3d1504ff;
	randoms[8] = 0x6367e309;
	randoms[9] = 0x4776fe20;
	randoms[10] = 0x648c154d;
	randoms[11] = 0x5c65c980;
	randoms[12] = 0x556e2d59;
	randoms[13] = 0x0e3bf852;
	randoms[14] = 0x45c4ad14;
	randoms[15] = 0x3560958c;
	randoms[16] = 0x3b73fe0a;
	randoms[17] = 0x61a9629c;
	randoms[18] = 0x625cb56d;
	randoms[19] = 0x5a7b7873;
	randoms[20] = 0x6f5212c1;
	randoms[21] = 0x1221ccd4;
	randoms[22] = 0x0f8a220f;
	randoms[23] = 0x22ad66e4;
	randoms[24] = 0x10093f5e;
	randoms[25] = 0x62fe2069;
	randoms[26] = 0x71b49060;
	randoms[27] = 0x4aa7106c;
	randoms[28] = 0x27394180;
	randoms[29] = 0x6d50766b;
	randoms[30] = 0x31d459ed;
	randoms[31] = 0x624e6371;

	srandom(time(NULL));
	gen_collisions(msg1, msg2);

	for (i = 0; i < 32; i ++)
		printf("%08x", to_big_endian(msg1[i]));
	puts("");

	for (i = 0; i < 32; i ++)
		printf("%08x", to_big_endian(msg2[i]));
	puts("");

	return 0;
}
