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



typedef struct
{
	const uint32_t diff;
	const uint32_t zero;
	const uint32_t one;
	const uint32_t prev;
	const uint32_t prev2;
} sufficient_cond;


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

uint32_t randoms[32];
uint32_t myrandom(size_t index)
{
	return randoms[index];
}

bool check_sc(uint32_t *state1, uint32_t *state2, size_t i, sufficient_cond *sc)
{
	if ((state1[i] & sc[i - 1].prev) != (state1[i - 1] & sc[i - 1].prev))
		return false;

	if ((state1[i] ^ state1[i - 2]) & sc[i - 1].prev2)
		return false;

	if ((state1[i] & sc[i - 1].one) != sc[i - 1].one)
		return false;

	if (state1[i] & sc[i - 1].zero)
		return false;

	if ((state1[i] - state2[i]) != sc[i - 1].diff)
		return false;

	return true;
}

void fix_sc(uint32_t *state1, uint32_t *state2, size_t i, sufficient_cond *sc)
{
	state1[i] |= sc[i - 1].one;
	state1[i] &= ~sc[i - 1].zero;
	state1[i] &= ~sc[i - 1].prev;
	state1[i] |= (state1[i - 1] & sc[i - 1].prev);
	state2[i] = state1[i] - sc[i - 1].diff;
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

	sufficient_cond sc[64] =
	{
		/*  -- */ /* diff, zero, one, prev, prev2 */
		/*  a1 */ { 0, 0, 0, 0 },
		/*  d1 */ { 0, 0, 0, 0 },
		/*  c1 */ { 0x00000000, 0x00800040, 0x00000000, 0x00000000, 0x00000000 },
		/*  b1 */ { 0x00000000, 0x00800040, 0x80080800, 0x0077f780, 0x00000000 },
		/*  a2 */ { 0x00000040, 0x02bfffc0, 0x88400025, 0x00000000, 0x00000000 },
		/*  d2 */ { 0x7f800040, 0x888043a4, 0x027fbc41, 0x7500001a, 0x00000000 },
		/*  c2 */ { 0x07800041, 0xfc0107df, 0x03fef820, 0x00000000, 0x00000000 },
		/*  b2 */ { 0x00827fff, 0xfe0eaabf, 0x01910540, 0x00000000, 0x00000000 },
		/*  a3 */ { 0x8000003f, 0x040f80c2, 0xfb102f3d, 0x00001000, 0x00000000 },
		/*  d3 */ { 0x7ffff000, 0x80802183, 0x401f9040, 0x00000000, 0x00000000 },
		/*  c3 */ { 0x40000000, 0xc00e3101, 0x000180c2, 0x00004000, 0x00000000 },
		/*  b3 */ { 0x80002080, 0xc007e080, 0x00081100, 0x03000000, 0x00000000 },
		/*  a4 */ { 0x7f000000, 0x82000180, 0x410fe008, 0x00000000, 0x00000000 },
		/*  d4 */ { 0x80000000, 0xa3040000, 0x000be188, 0x00000000, 0x00000000 },
		/*  c4 */ { 0x80007ff8, 0x82000008, 0x21008000, 0x00000000, 0x00000000 },
		/*  b4 */ { 0xa0000000, 0x80000000, 0x20000000, 0x00000000, 0x00000000 },
		/*  a5 */ { 0x80000000, 0x80020000, 0x00000000, 0x00008008, 0x00000000 },
		/*  d5 */ { 0, 0, 0, 0, 0 },
		/*  c5 */ { 0x7ffe0000, 0x80020000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b5 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a6 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d6 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c6 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b6 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a9 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d9 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c9 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b9 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* a13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* d13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* c13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* a14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* d14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* c14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* a15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* d15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* c15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b15 */ { 0x80000000, 0x02000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a16 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d16 */ { 0x7e000000, 0x02000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c16 */ { 0x7e000000, 0, 0, 0 },
		/* b16 */ { 0x7e000000, 0, 0, 0 },
	};

	while (true)
	{
		ok = true;

		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (1) %d\n", attempts);

		/* C1 to A5 */
		for (i = 3; i <= 17; i ++)
		{
			state1[i] = myrandom(i - 3);
			fix_sc(state1, state2, i, sc);
		}

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
		if (state1[19] & sc[18].zero)
			continue;
		if (state1[19] - state2[19] != sc[18].diff)
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

			if (!check_sc(state1, state2, i, sc))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A9 to B12 */
		for (i = 33; i <= 48; i ++)
		{
			state1[i] = rot_left(md5_h(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_h(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i, sc))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[md5_msg_index[48]] + md5_add[48], 6) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[md5_msg_index[48]] + md5_add[48], 6) + state2[48];
		if ((state1[49] ^ state1[47]) & sc[48].prev2)
			continue;
		if ((state1[49] - state2[49]) != sc[48].diff)
			continue;


		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[md5_msg_index[49]] + md5_add[49], 10) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[md5_msg_index[49]] + md5_add[49], 10) + state2[49];
		if (!((state1[50] ^ state1[48]) & sc[49].prev2))
			continue;
		if ((state1[50] ^ state2[50]) != sc[49].diff)
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[md5_msg_index[50]] + md5_add[50], 15) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[md5_msg_index[50]] + md5_add[50], 15) + state2[50];
		if ((state1[51] ^ state1[49]) & sc[50].prev2)
			continue;
		if ((state1[51] ^ state2[51]) != sc[50].diff)
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[md5_msg_index[51]] + md5_add[51], 21) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[md5_msg_index[51]] + md5_add[51], 21) + state2[51];
		if ((state1[52] ^ state1[50]) & sc[51].prev2)
			continue;
		if ((state1[52] ^ state2[52]) != sc[51].diff)
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[md5_msg_index[52]] + md5_add[52], 6) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[md5_msg_index[52]] + md5_add[52], 6) + state2[52];
		if ((state1[53] ^ state1[51]) & sc[52].prev2)
			continue;
		if ((state1[53] ^ state2[53]) != sc[52].diff)
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[md5_msg_index[53]] + md5_add[53], 10) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[md5_msg_index[53]] + md5_add[53], 10) + state2[53];
		if ((state1[54] ^ state1[52]) & sc[53].prev2)
			continue;
		if ((state1[54] ^ state2[54]) != sc[53].diff)
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[md5_msg_index[54]] + md5_add[54], 15) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[md5_msg_index[54]] + md5_add[54], 15) + state2[54];
		if ((state1[55] ^ state1[53]) & sc[54].prev2)
			continue;
		if ((state1[55] ^ state2[55]) != sc[54].diff)
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[md5_msg_index[55]] + md5_add[55], 21) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[md5_msg_index[55]] + md5_add[55], 21) + state2[55];
		if ((state1[56] ^ state1[54]) & sc[55].prev2)
			continue;
		if ((state1[56] ^ state2[56]) != sc[55].diff)
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[md5_msg_index[56]] + md5_add[56], 6) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[md5_msg_index[56]] + md5_add[56], 6) + state2[56];
		if ((state1[57] ^ state1[55]) & sc[56].prev2)
			continue;
		if ((state1[57] ^ state2[57]) != sc[56].diff)
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[md5_msg_index[57]] + md5_add[57], 10) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[md5_msg_index[57]] + md5_add[57], 10) + state2[57];
		if ((state1[58] ^ state1[56]) & sc[57].prev2)
			continue;
		if ((state1[58] ^ state2[58]) != sc[57].diff)
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[md5_msg_index[58]] + md5_add[58], 15) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[md5_msg_index[58]] + md5_add[58], 15) + state2[58];
		if ((state1[59] ^ state1[57]) & sc[58].prev2)
			continue;
		if ((state1[59] ^ state2[59]) != sc[58].diff)
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[md5_msg_index[59]] + md5_add[59], 21) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[md5_msg_index[59]] + md5_add[59], 21) + state2[59];
		if (state1[60] & sc[59].zero)
			continue;
		if ((state1[60] ^ state2[60]) != sc[59].diff)
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[md5_msg_index[60]] + md5_add[60], 6) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[md5_msg_index[60]] + md5_add[60], 6) + state2[60];
		if ((state1[61] ^ state2[61]) != sc[60].diff)
			continue;

		/* D16 */
		state1[62] = rot_left(md5_i(state1[61], state1[60], state1[59]) + state1[58] + msg1[md5_msg_index[61]] + md5_add[61], 10) + state1[61];
		state2[62] = rot_left(md5_i(state2[61], state2[60], state2[59]) + state2[58] + msg2[md5_msg_index[61]] + md5_add[61], 10) + state2[61];
		if (state1[62] & sc[61].zero)
			continue;
		if ((state1[62] - state2[62]) != sc[61].diff)
			continue;

		/* C16 */
		state1[63] = rot_left(md5_i(state1[62], state1[61], state1[60]) + state1[59] + msg1[md5_msg_index[62]] + md5_add[62], 15) + state1[62];
		state2[63] = rot_left(md5_i(state2[62], state2[61], state2[60]) + state2[59] + msg2[md5_msg_index[62]] + md5_add[62], 15) + state2[62];
		if (((state1[63] + md5_iv[2]) & 0x86000000) != (((state1[62] + md5_iv[3]) & 0x80000000) | 0x02000000))
			continue;
		if ((state1[63] - state2[63]) != sc[62].diff)
			continue;

		/* B16 */
		state1[64] = rot_left(md5_i(state1[63], state1[62], state1[61]) + state1[60] + msg1[md5_msg_index[63]] + md5_add[63], 21) + state1[63];
		state2[64] = rot_left(md5_i(state2[63], state2[62], state2[61]) + state2[60] + msg2[md5_msg_index[63]] + md5_add[63], 21) + state2[63];
		if (((state1[64] + md5_iv[1]) & 0x86000020) != ((state1[63] + md5_iv[2]) & 0x80000000))
			continue;
		if ((state1[64] - state2[64]) != sc[63].diff)
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

	sufficient_cond sc[64] =
	{
		/*  -- */ /* diff, zero, one, prev, prev2 */
		/*  a1 */ { 0x7e000000, 0x0a000820, 0x84200000, 0x00000000 },
		/*  d1 */ { 0x7dffffe0, 0x02208026, 0x8c000800, 0x701f10c0 },
		/*  c1 */ { 0x7dfef7e0, 0x40201080, 0xbe1f0966, 0x00000018 },
		/*  b1 */ { 0x7dffffe2, 0x443b19ee, 0xba040010, 0x00000601 },
		/*  a2 */ { 0x7ffffcbf, 0xb41011af, 0x482f0e50, 0x00000000 },
		/*  d2 */ { 0x80110000, 0x9a1113a9, 0x04220c56, 0x00000000 },
		/*  c2 */ { 0x88000040, 0x083201c0, 0x96011e01, 0x01808000 },
		/*  b2 */ { 0x80818000, 0x1b810001, 0x843283c0, 0x00000002 },
		/*  a3 */ { 0x7fffffbf, 0x03828202, 0x9c0101c1, 0x00001000 },
		/*  d3 */ { 0x7ffff000, 0x00041003, 0x878383c0, 0x00000000 },
		/*  c3 */ { 0x80000000, 0x00021000, 0x800583c3, 0x00086000 },
		/*  b3 */ { 0x80002080, 0x0007e000, 0x80081080, 0x7f000000 },
		/*  a4 */ { 0x7f000000, 0x80000080, 0x3f0fe008, 0x00000000 },
		/*  d4 */ { 0x80000000, 0xbf040000, 0x400be088, 0x00000000 },
		/*  c4 */ { 0x7fff7ff8, 0x82008008, 0x7d000000, 0x00000000 },
		/*  b4 */ { 0xa0000000, 0, 0, 0 },
		/*  a5 */ { 0x80000000, 0, 0, 0 },
		/*  d5 */ { 0x80000000, 0, 0, 0 },
		/*  c5 */ { 0x7ffe0000, 0x80020000, 0, 0 },
		/*  b5 */ { 0x80000000, 0x80000000, 0, 0 },
		/*  a6 */ { 0x80000000, 0, 0, 0 },
		/*  d6 */ { 0x80000000, 0x80000000, 0, 0 },
		/*  c6 */ { 0x00000000, 0x80000000, 0, 0 },
		/*  b6 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b7 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b8 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a9 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d9 */ { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c9 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b9 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b10 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b11 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c12 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b12 */ { 0x80000000, 0, 0, 0 },
		/* a13 */ { 0x80000000, 0, 0, 0 },
		/* d13 */ { 0x80000000, 0, 0, 0 },
		/* c13 */ { 0x80000000, 0, 0, 0 },
		/* b13 */ { 0x80000000, 0, 0, 0 },
		/* a14 */ { 0x80000000, 0, 0, 0 },
		/* d14 */ { 0x80000000, 0, 0, 0 },
		/* c14 */ { 0x80000000, 0, 0, 0 },
		/* b14 */ { 0x80000000, 0, 0, 0 },
		/* a15 */ { 0x80000000, 0, 0, 0 },
		/* d15 */ { 0x80000000, 0, 0, 0 },
		/* c15 */ { 0x80000000, 0, 0, 0 },
		/* b15 */ { 0x80000000, 0, 0, 0 },
		/* a16 */ { 0x80000000, 0, 0, 0 },
		/* d16 */ { 0x00000000, 0, 0, 0 },
		/* c16 */ { 0x00000000, 0, 0, 0 },
		/* b16 */ { 0x00000000, 0, 0, 0 },
	};

	while (true)
	{
		ok = true;
		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (2) %d\n", attempts);

		/* A1 to B4 */
		for (i = 0; i < 16; i ++)
		{
			state1[i + 1] = myrandom(i + 16);
			fix_sc(state1, state2, i + 1, sc);
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
		if ((state1[17] ^ state2[17]) != sc[16].diff)
			continue;

		/* D5 */
		state1[18] = rot_left(md5_g(state1[17], state1[16], state1[15]) + state1[14] + msg1[22] + md5_add[17], md5_shift[17]) + state1[17];
		state2[18] = rot_left(md5_g(state2[17], state2[16], state2[15]) + state2[14] + msg2[22] + md5_add[17], md5_shift[17]) + state2[17];
		if ((state1[18] & 0xa0020000) != ((state1[17] & 0x20000000) | 0x00020000))
			continue;
		if ((state1[18] ^ state2[18]) != sc[17].diff)
			continue;

		/* C5 to B8 */
		for (i = 19; i <= 32; i ++)
		{
			state1[i] = rot_left(md5_g(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state1[i - 1];
			state2[i] = rot_left(md5_g(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[16 + md5_msg_index[i - 1]] + md5_add[i - 1], md5_shift[i - 1]) + state2[i - 1];

			if (!check_sc(state1, state2, i, sc))
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

			if (!check_sc(state1, state2, i, sc))
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
		if ((state1[48] ^ state2[48]) != sc[47].diff)
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[16] + md5_add[48], md5_shift[48]) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[16] + md5_add[48], md5_shift[48]) + state2[48];
		if ((state1[49] & 0x80000000) != (state1[47] & 0x80000000))
			continue;
		if ((state1[49] ^ state2[49]) != sc[48].diff)
			continue;

		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[23] + md5_add[49], md5_shift[49]) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[23] + md5_add[49], md5_shift[49]) + state2[49];
		if ((state1[50] ^ state2[50]) != sc[49].diff)
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[30] + md5_add[50], md5_shift[50]) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[30] + md5_add[50], md5_shift[50]) + state2[50];
		if ((state1[51] & 0x80000000) != (state1[49] & 0x80000000))
			continue;
		if ((state1[51] ^ state2[51]) != sc[50].diff)
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[21] + md5_add[51], md5_shift[51]) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[21] + md5_add[51], md5_shift[51]) + state2[51];
		if ((state1[52] & 0x80000000) != (state1[50] & 0x80000000))
			continue;
		if ((state1[52] ^ state2[52]) != sc[51].diff)
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[28] + md5_add[52], md5_shift[52]) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[28] + md5_add[52], md5_shift[52]) + state2[52];
		if ((state1[53] & 0x80000000) != (state1[51] & 0x80000000))
			continue;
		if ((state1[53] ^ state2[53]) != sc[52].diff)
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[19] + md5_add[53], md5_shift[53]) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[19] + md5_add[53], md5_shift[53]) + state2[53];
		if ((state1[54] & 0x80000000) != (state1[52] & 0x80000000))
			continue;
		if ((state1[54] ^ state2[54]) != sc[53].diff)
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[26] + md5_add[54], md5_shift[54]) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[26] + md5_add[54], md5_shift[54]) + state2[54];
		if ((state1[55] & 0x80000000) != (state1[53] & 0x80000000))
			continue;
		if ((state1[55] ^ state2[55]) != sc[54].diff)
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[17] + md5_add[55], md5_shift[55]) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[17] + md5_add[55], md5_shift[55]) + state2[55];
		if ((state1[56] & 0x80000000) != (state1[54] & 0x80000000))
			continue;
		if ((state1[56] ^ state2[56]) != sc[55].diff)
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[24] + md5_add[56], md5_shift[56]) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[24] + md5_add[56], md5_shift[56]) + state2[56];
		if ((state1[57] & 0x80000000) != (state1[55] & 0x80000000))
			continue;
		if ((state1[57] ^ state2[57]) != sc[56].diff)
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[31] + md5_add[57], md5_shift[57]) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[31] + md5_add[57], md5_shift[57]) + state2[57];
		if ((state1[58] & 0x80000000) != (state1[56] & 0x80000000))
			continue;
		if ((state1[58] ^ state2[58]) != sc[57].diff)
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[22] + md5_add[58], md5_shift[58]) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[22] + md5_add[58], md5_shift[58]) + state2[58];
		if ((state1[59] & 0x80000000) != (state1[57] & 0x80000000))
			continue;
		if ((state1[59] ^ state2[59]) != sc[58].diff)
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[29] + md5_add[59], md5_shift[59]) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[29] + md5_add[59], md5_shift[59]) + state2[59];
		if ((state1[60] ^ state2[60]) != sc[59].diff)
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[20] + md5_add[60], md5_shift[60]) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[20] + md5_add[60], md5_shift[60]) + state2[60];
		if ((state1[61] ^ state2[61]) != sc[60].diff)
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
