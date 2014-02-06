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

uint32_t (*md5_round_func[64])(uint32_t x, uint32_t y, uint32_t z) =
{
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
};



uint32_t randoms[32];
uint32_t myrandom(size_t index)
{
	return randoms[index];
}

typedef struct
{
	uint32_t diff;
	uint32_t zero;
	uint32_t one;
	uint32_t prev1;
	uint32_t prev2;
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

bool check_sc(
	uint32_t *state1,
	uint32_t *state2,
	size_t i,
	sufficient_cond *sc)
{
	if ((state1[i] & sc[i].prev1) != (state1[i - 1] & sc[i].prev1))
		return false;

	if ((state1[i] ^ state1[i - 2]) & sc[i].prev2)
		return false;

	if ((state1[i] & sc[i].one) != sc[i].one)
		return false;

	if (state1[i] & sc[i].zero)
		return false;

	if ((state1[i] - state2[i]) != sc[i].diff)
		return false;

	return true;
}

void fix_sc(
	uint32_t *state1,
	uint32_t *state2,
	size_t i,
	sufficient_cond *sc)
{
	state1[i] |= sc[i].one;

	state1[i] &= ~sc[i].zero;

	state1[i] &= ~sc[i].prev1;
	state1[i] |= (state1[i - 1] & sc[i].prev1);

	state2[i] = state1[i] - sc[i].diff;
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
		/*  -- */ /* diff, zero, one, prev1, prev2 */
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
		/* d13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 }, /* missing? !((state[i]-state[i-2])&80000000) */
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
		/* c16 */ { 0x7e000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b16 */ { 0x7e000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
	};

	while (true)
	{
		ok = true;

		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (1) %d\n", attempts);

		/* C1 to A5 */
		for (i = 2; i < 17; i ++)
		{
			state1[i] = myrandom(i - 2);
			fix_sc(state1, state2, i, sc);
		}

		for (i = 6; i < 16; i ++)
		{
			msg1[i] = rot_right(state1[i] - state1[i - 1], md5_shift[i]) - (*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) - state1[i - 4] - md5_add[i];
			msg2[i] = rot_right(state2[i] - state2[i - 1], md5_shift[i]) - (*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) - state2[i - 4] - md5_add[i];

			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* D5 */
		state1[17] = rot_left((*md5_round_func[17])(state1[16], state1[15], state1[14]) + state1[13] + msg1[6] + md5_add[17], 9) + state1[16];
		state2[17] = rot_left((*md5_round_func[17])(state2[16], state2[15], state2[14]) + state2[13] + msg2[6] + md5_add[17], 9) + state2[16];
		if ((state1[17] & 0xa0020000) != (0x00020000 | (state1[16] & 0x20000000)))
			continue;
		if ((state1[17] ^ state2[17]) != 0x80000000)
			continue;

		/* C5 */
		state1[18] = rot_left((*md5_round_func[18])(state1[17], state1[16], state1[15]) + state1[14] + msg1[11] + md5_add[18], 14) + state1[17];
		state2[18] = rot_left((*md5_round_func[18])(state2[17], state2[16], state2[15]) + state2[14] + msg2[11] + md5_add[18], 14) + state2[17];
		if (state1[18] & sc[18].zero)
			continue;
		if (state1[18] - state2[18] != sc[18].diff)
			continue;

		/* B5 */
		state1[19] = myrandom(15);
		state2[19] = state1[19] - 0x80000000;

		state1[0] = rot_left((*md5_round_func[0])(state1[-1], state1[-2], state1[-3]) + state1[-4] + msg1[0] + md5_add[0], 7) + state1[-1];
		state2[0] = state1[0];

		state1[1] = rot_left((*md5_round_func[1])(state1[0], state1[-1], state1[-2]) + state1[-3] + msg1[1] + md5_add[1], 12) + state1[0];
		state2[1] = state1[1];

		msg1[0] = rot_right(state1[19] - state1[18], 20) - (*md5_round_func[19])(state1[18], state1[17], state1[16]) - state1[15] - md5_add[19];
		msg2[0] = rot_right(state2[19] - state2[18], 20) - (*md5_round_func[19])(state2[18], state2[17], state2[16]) - state2[15] - md5_add[19];
		if ((msg1[0] ^ msg2[0]) != message_delta[0])
			continue;

		msg1[1] = rot_right(state1[16] - state1[15], md5_shift[16]) - (*md5_round_func[16])(state1[15], state1[14], state1[13]) - state1[12] - md5_add[16];
		msg2[1] = rot_right(state2[16] - state2[15], md5_shift[16]) - (*md5_round_func[16])(state2[15], state2[14], state2[13]) - state2[12] - md5_add[16];
		if ((msg1[1] ^ msg2[1]) != message_delta[1])
			continue;

		for (i = 2; i < 6; i ++)
		{
			msg1[i] = rot_right(state1[i] - state1[i - 1], md5_shift[i]) - (*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) - state1[i - 4] - md5_add[i];
			msg2[i] = rot_right(state2[i] - state2[i - 1], md5_shift[i]) - (*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) - state2[i - 4] - md5_add[i];

			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A6 to B16 */
		for (i = 20; i < 64; i ++)
		{
			state1[i] = rot_left((*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md5_msg_index[i]] + md5_add[i], md5_shift[i]) + state1[i - 1];
			state2[i] = rot_left((*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md5_msg_index[i]] + md5_add[i], md5_shift[i]) + state2[i - 1];

			if (!check_sc(state1, state2, i, sc))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
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
		/*  -- */ /* diff, zero, one, prev1, prev2 */
		/*  a1 */ { 0x7e000000, 0x0a000820, 0x84200000, 0x00000000, 0x00000000 },
		/*  d1 */ { 0x7dffffe0, 0x02208026, 0x8c000800, 0x701f10c0, 0x00000000 },
		/*  c1 */ { 0x7dfef7e0, 0x40201080, 0xbe1f0966, 0x00000018, 0x00000000 },
		/*  b1 */ { 0x7dffffe2, 0x443b19ee, 0xba040010, 0x00000601, 0x00000000 },
		/*  a2 */ { 0x7ffffcbf, 0xb41011af, 0x482f0e50, 0x00000000, 0x00000000 },
		/*  d2 */ { 0x80110000, 0x9a1113a9, 0x04220c56, 0x00000000, 0x00000000 },
		/*  c2 */ { 0x88000040, 0x083201c0, 0x96011e01, 0x01808000, 0x00000000 },
		/*  b2 */ { 0x80818000, 0x1b810001, 0x843283c0, 0x00000002, 0x00000000 },
		/*  a3 */ { 0x7fffffbf, 0x03828202, 0x9c0101c1, 0x00001000, 0x00000000 },
		/*  d3 */ { 0x7ffff000, 0x00041003, 0x878383c0, 0x00000000, 0x00000000 },
		/*  c3 */ { 0x80000000, 0x00021000, 0x800583c3, 0x00086000, 0x00000000 },
		/*  b3 */ { 0x80002080, 0x0007e000, 0x80081080, 0x7f000000, 0x00000000 },
		/*  a4 */ { 0x7f000000, 0x80000080, 0x3f0fe008, 0x00000000, 0x00000000 },
		/*  d4 */ { 0x80000000, 0xbf040000, 0x400be088, 0x00000000, 0x00000000 },
		/*  c4 */ { 0x7fff7ff8, 0x82008008, 0x7d000000, 0x00000000, 0x00000000 },
		/*  b4 */ { 0xa0000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a5 */ { 0x80000000, 0x80020000, 0x00000000, 0x00008008, 0x00000000 },
		/*  d5 */ { 0x80000000, 0x80000000, 0x00020000, 0x20000000, 0x00000000 },
		/*  c5 */ { 0x7ffe0000, 0x80020000, 0x00000000, 0x00000000, 0x00000000 },
		/*  b5 */ { 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  a6 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  d6 */ { 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		/*  c6 */ { 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
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
		/* d13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b13 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* a14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* d14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* c14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b14 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* a15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* d15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* c15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
		/* b15 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* a16 */ { 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* d16 */ { 0x82000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* c16 */ { 0x82000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		/* b16 */ { 0x82000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
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
			/* generate random state */
			state1[i] = myrandom(i + 16);

			/* do simple message modification */
			fix_sc(state1, state2, i, sc);
		}

		for (i = 0; i < 16; i ++)
		{
			msg1[16 + i] = rot_right(state1[i] - state1[i - 1], md5_shift[i]) - (*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) - state1[i - 4] - md5_add[i];
			msg2[16 + i] = rot_right(state2[i] - state2[i - 1], md5_shift[i]) - (*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) - state2[i - 4] - md5_add[i];

			if ((msg1[16 + i] ^ msg2[16 + i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* A5 to B16 */
		for (i = 16; i < 32; i ++)
		{
			state1[i] = rot_left((*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[16 + md5_msg_index[i]] + md5_add[i], md5_shift[i]) + state1[i - 1];
			state2[i] = rot_left((*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[16 + md5_msg_index[i]] + md5_add[i], md5_shift[i]) + state2[i - 1];

			if (!check_sc(state1, state2, i, sc))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		return;
	}
}

void gen_collisions(uint32_t msg1[32], uint32_t msg2[32])
{
	uint32_t state1real[68], state2real[68];
	uint32_t *state1, *state2;

	state1 = state1real + 4;
	state2 = state2real + 4;
	state1[-4] = state2[-4] = md5_iv[0];
	state1[-3] = state2[-3] = md5_iv[3];
	state1[-2] = state2[-2] = md5_iv[2];
	state1[-1] = state2[-1] = md5_iv[1];

	block1(msg1, msg2, state1, state2);

	state1[-4] += state1[60];
	state1[-3] += state1[61];
	state1[-2] += state1[62];
	state1[-1] += state1[63];

	state2[-4] += state2[60];
	state2[-3] += state2[61];
	state2[-2] += state2[62];
	state2[-1] += state2[63];

	block2(msg1, msg2, state1, state2);
}

int main(int argc, char *argv[])
{
	size_t i;
	uint32_t msg1[32], msg2[32];

	#define dataset_num 1

	uint32_t dataset[] =
	{
		#if dataset_num == 1
			0x272041c9, 0x36d69572, 0x0967f364, 0x471aad20,
			0x58b34b54, 0x2cad4fe2, 0x57085139, 0x3d1504ff,
			0x6367e309, 0x4776fe20, 0x648c154d, 0x5c65c980,
			0x556e2d59, 0x0e3bf852, 0x45c4ad14, 0x3560958c,
			0x3b73fe0a, 0x61a9629c, 0x625cb56d, 0x5a7b7873,
			0x6f5212c1, 0x1221ccd4, 0x0f8a220f, 0x22ad66e4,
			0x10093f5e, 0x62fe2069, 0x71b49060, 0x4aa7106c,
			0x27394180, 0x6d50766b, 0x31d459ed, 0x624e6371,
		#elif dataset_num == 2
			0x7824d6b9, 0x78c73729, 0x03226be3, 0x014aad9a,
			0x68f40279, 0x778ee9d0, 0x43542dca, 0x6f3dd901,
			0x67d85ab1, 0x5f450cf5, 0x34e676bd, 0x075ee791,
			0x2c8acaf0, 0x2a794306, 0x68f472ce, 0x3273a16b,
			0x18e06289, 0x4a084bc9, 0x7b2303db, 0x1dfa6355,
			0x4e696eb4, 0x619325bf, 0x6bf41cc5, 0x1e629b4c,
			0x28b42a89, 0x59326132, 0x7ce85364, 0x1ef56767,
			0x183fd02e, 0x1e909a31, 0x0f0fcdd4, 0x2558dadc
		#elif dataset_num == 3
			0x75e52499, 0x7ca0933d, 0x016c740e, 0x5b44c205,
			0x32aa72ab, 0x2bd6c5d5, 0x104b50f4, 0x7271875e,
			0x2d792dc6, 0x1243f599, 0x094ced24, 0x2b46b153,
			0x333c1f16, 0x4d43bd35, 0x42676890, 0x3b1c7317,
			0x32fc565a, 0x3b6f69d0, 0x5b873257, 0x5edaaecc,
			0x79e911ce, 0x2fcbfe97, 0x5ac2bae9, 0x4982c9be,
			0x3f001867, 0x68510cd4, 0x084ed6b4, 0x5f8f81f4,
			0x7130746b, 0x64f3baed, 0x76fbcb63, 0x6a589b6f
		#elif dataset_num == 4
			0x5b47a1fd, 0x0de88ffc, 0x031d79a6, 0x65e384be,
			0x320f61af, 0x7e4a4105, 0x119bf388, 0x7fc29924,
			0x75e9af5b, 0x11d81f6c, 0x15ceecdc, 0x70593137,
			0x07fcba9d, 0x7af7631b, 0x490fd1d5, 0x0e5c3aaf,
			0x79565315, 0x4896b46c, 0x0a2b271b, 0x2ec6b819,
			0x4ae2f1dc, 0x76b03f54, 0x78ee153f, 0x20e20c8f,
			0x24ad01ca, 0x00a36491, 0x4b56722d, 0x0e7cc8ec,
			0x5f40f792, 0x31ce8fb9, 0x51645a8d, 0x3f0195d4
		#endif
	};

	for (i = 0; i < 32; i ++)
		randoms[i] = dataset[i];

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
