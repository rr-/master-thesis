#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "common.h"
#include "sc.h"
#include "tick.h"

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



void recover_msg(
	uint32_t *const msg1,
	uint32_t *const msg2,
	const uint32_t *const state1,
	const uint32_t *const state2,
	const size_t i)
{
	msg1[i] = rot_right(state1[i] - state1[i - 1], md5_shift[i])
		- (*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3])
		- state1[i - 4]
		- md5_add[i];

	msg2[i] = rot_right(state2[i] - state2[i - 1], md5_shift[i])
		- (*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3])
		- state2[i - 4]
		- md5_add[i];
}

void recover_state(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const size_t i)
{
	state1[i] =
		rot_left(
			(*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3])
				+ state1[i - 4]
				+ msg1[md5_msg_index[i]]
				+ md5_add[i],
			md5_shift[i])
		+ state1[i - 1];

	state2[i] =
		rot_left(
			(*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3])
				+ state2[i - 4]
				+ msg2[md5_msg_index[i]]
				+ md5_add[i],
			md5_shift[i])
		+ state2[i - 1];
}

bool check_msg(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	const size_t i,
	const uint32_t *const message_delta)
{
	return (msg1[i] ^ msg2[i]) == message_delta[i];
}



/* prepare differences and bitmasks for sufficient conditions based on
 * human-readable table */
void block1_fill_sc(compiled_sufficient_cond *const sc)
{
	/* differences and sufficient conditions as in wang's paper */
	const sufficient_cond sc_raw[] =
	{
		/* a1 */ {0x00000000, "-------- -------- -------- --------"},
		/* d1 */ {0x00000000, "-------- -------- -------- --------"},
		/* c1 */ {0x00000000, "-------- 0------- ----0--- -0------"},
		/* b1 */ {0x00000000, "1------- 0ppp1ppp pppp1ppp p0------"},
		/* a2 */ {0x00000040, "1000100- 01000000 00000000 001--1-1"},
		/* d2 */ {0x7f800040, "0ppp0p1p 01111111 10111100 010pp0p1"},
		/* c2 */ {0x07800041, "00000011 11111110 11111000 00100000"},
		/* b2 */ {0x00827fff, "00000001 1--10001 0-0-0101 01000000"},
		/* a3 */ {0x8000003f, "11111011 ---10000 0-1p1111 00111101"},
		/* d3 */ {0x7ffff000, "01------ 0--11111 1-01---0 01----00"},
		/* c3 */ {0x40000000, "00------ ----0001 1p00---0 11----10"},
		/* b3 */ {0x80002080, "00----pp ----1000 0001---1 0-------"},
		/* a4 */ {0x7f000000, "01----01 ----1111 111----0 0---1---"},
		/* d4 */ {0x80000000, "0-0---00 ----1011 111----1 1---1---"},
		/* c4 */ {0x80007ff8, "0-1---01 -------- 1------- ----0---"},
		/* b4 */ {0xa0000000, "0-1----- -------- -------- --------"},
		/* a5 */ {0x80000000, "0------- ------0- p------- ----p---"},
		/* d5 */ {0x80000000, "0-p----- ------1- -------- --------"},
		/* c5 */ {0x7ffe0000, "0------- ------0- -------- --------"},
		/* b5 */ {0x80000000, "0------- -------- -------- --------"},
		/* a6 */ {0x80000000, "0------- ------p- -------- --------"},
		/* d6 */ {0x80000000, "0------- -------- -------- --------"},
		/* c6 */ {0x00000000, "0------- -------- -------- --------"},
		/* b6 */ {0x00000000, "P------- -------- -------- --------"},
		/* a7 */ {0x00000000, "-------- -------- -------- --------"},
		/* d7 */ {0x00000000, "-------- -------- -------- --------"},
		/* c7 */ {0x00000000, "-------- -------- -------- --------"},
		/* b7 */ {0x00000000, "-------- -------- -------- --------"},
		/* a8 */ {0x00000000, "-------- -------- -------- --------"},
		/* d8 */ {0x00000000, "-------- -------- -------- --------"},
		/* c8 */ {0x00000000, "-------- -------- -------- --------"},
		/* b8 */ {0x00000000, "-------- -------- -------- --------"},
		/* a9 */ {0x00000000, "-------- -------- -------- --------"},
		/* d9 */ {0x00000000, "-------- -------- -------- --------"},
		/* c9 */ {0x80000000, "-------- -------- -------- --------"},
		/* b9 */ {0x80000000, "-------- -------- -------- --------"},
		/* a10*/ {0x80000000, "-------- -------- -------- --------"},
		/* d10*/ {0x80000000, "-------- -------- -------- --------"},
		/* c10*/ {0x80000000, "-------- -------- -------- --------"},
		/* b10*/ {0x80000000, "-------- -------- -------- --------"},
		/* a11*/ {0x80000000, "-------- -------- -------- --------"},
		/* d11*/ {0x80000000, "-------- -------- -------- --------"},
		/* c11*/ {0x80000000, "-------- -------- -------- --------"},
		/* b11*/ {0x80000000, "-------- -------- -------- --------"},
		/* a12*/ {0x80000000, "-------- -------- -------- --------"},
		/* d12*/ {0x80000000, "-------- -------- -------- --------"},
		/* c12*/ {0x80000000, "-------- -------- -------- --------"},
		/* b12*/ {0x80000000, "f------- -------- -------- --------"},
		/* a13*/ {0x80000000, "f------- -------- -------- --------"},
		/* d13*/ {0x80000000, "F------- -------- -------- --------"},
		/* c13*/ {0x80000000, "f------- -------- -------- --------"},
		/* b13*/ {0x80000000, "f------- -------- -------- --------"},
		/* a14*/ {0x80000000, "f------- -------- -------- --------"},
		/* d14*/ {0x80000000, "f------- -------- -------- --------"},
		/* c14*/ {0x80000000, "f------- -------- -------- --------"},
		/* b14*/ {0x80000000, "f------- -------- -------- --------"},
		/* a15*/ {0x80000000, "f------- -------- -------- --------"},
		/* d15*/ {0x80000000, "f------- -------- -------- --------"},
		/* c15*/ {0x80000000, "f------- -------- -------- --------"},
		/* b15*/ {0x80000000, "F-----0- -------- -------- --------"},
		/* a16*/ {0x80000000, "f----01- -------- -------- --------"}, /* checked manually */
		/* d16*/ {0x82000000, "f-----0- -------- -------- --------"}, /* checked manually */
		/* c16*/ {0x82000000, "p------- -------- -------- --------"}, /* checked manually */
		/* b16*/ {0x82000000, "-------- -------- -------- --------"}, /* checked manually */
	};

	compile_sc(sc_raw, sc, 64);
}

__attribute__((always_inline)) inline bool block1_amm(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const compiled_sufficient_cond *const sc,
	const uint32_t *const message_delta,
	bool full)
{
	size_t i;

	if (!full)
	{
		/* a5 */
		state1[16] = random();
		fix_sc(state1, state2, 16, sc);

		/* recover 1st message word from internal state of a5 */
		recover_msg(msg1 + 1 - 16, msg2 + 1 - 16, state1, state2, 16);
		if (!check_msg(msg1, msg2, 1, message_delta))
			return false;

		/* d5 to c5 */
		for (i = 17; i < 19; i ++)
		{
			recover_state(msg1, msg2, state1, state2, i);
			if (!check_sc(state1, state2, i, sc))
				return false;
		}
	}

	/* b5 */
	state1[19] = random();
	fix_sc(state1, state2, 19, sc);

	/* recover 0th message word from internal state of b5 */
	recover_msg(msg1 + 0 - 19, msg2 + 0 - 19, state1, state2, 19);
	if (!check_msg(msg1, msg2, 0, message_delta))
		return false;

	/* a1, d1 */
	recover_state(msg1, msg2, state1, state2, 0);
	recover_state(msg1, msg2, state1, state2, 1);

	/* recover rest of message words from internal state */
	for (i = 2; i < 6; i ++)
	{
		recover_msg(msg1, msg2, state1, state2, i);
		if (!check_msg(msg1, msg2, i, message_delta))
			return false;
	}

	/* check round 2 and round 3 output differences */
	/* a6 to b7 (partial) or a6 to b15 (full) */
	for (i = 20; i < (full ? 60 : 26); i ++)
	{
		recover_state(msg1, msg2, state1, state2, i);
		if (!check_sc(state1, state2, i, sc))
			return false;
	}

	/* check final SCs on a16 to b16 manually */
	if (full)
	{
		for (i = 60; i < 64; i ++)
			recover_state(msg1, msg2, state1, state2, i);

		for (i = 60; i < 64; i ++)
		{
			state1[i] += state1[i-64];
			state2[i] += state2[i-64];
		}

		/* aa0 */
		if ((state1[60] - state2[60]) != 0x80000000)
			return false;

		/* dd0 */
		if (bit_at(state1[61], 25) != 0)
			return false;
		if ((state1[61] - state2[61]) != 0x7e000000)
			return false;

		/* cc0 */
		if (bit_at(state1[62], 25) != 1)
			return false;
		if (bit_at(state1[62], 26) != 0)
			return false;
		if (bit_at(state1[62], 31) != bit_at(state1[61], 31))
			return false;
		if ((state1[62] - state2[62]) != 0x7e000000)
			return false;

		/* bb0 */
		if (bit_at(state1[63], 5) != 0)
			return false;
		if (bit_at(state1[63], 25) != 0)
			return false;
		if (bit_at(state1[63], 26) != 0)
			return false;
		if (bit_at(state1[63], 31) != bit_at(state1[62], 31))
			return false;
		if ((state1[63] - state2[63]) != 0x7e000000)
			return false;

		for (i = 60; i < 64; i ++)
		{
			state1[i] -= state1[i-64];
			state2[i] -= state2[i-64];
		}
	}

	return true;
}

__attribute__((always_inline)) inline bool block1_try(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const compiled_sufficient_cond *const sc,
	const uint32_t *const message_delta)
{
	tick_context tc;
	size_t i;
	bool ok;

	tick_init(&tc, 10000000);

	/* round 1 */
	/* c1 to a4 */
	for (i = 2; i < 16; i ++)
	{
		/* generate random state */
		state1[i] = random();

		/* do simple message modification */
		fix_sc(state1, state2, i, sc);
	}

	/* recover message words from internal state */
	for (i = 6; i < 16; i ++)
	{
		recover_msg(msg1, msg2, state1, state2, i);
		if (!check_msg(msg1, msg2, i, message_delta))
			return false;
	}

	/* deep testing */
	for (i = 0; i < 300; i ++)
	{
		ok = block1_amm(msg1, msg2, state1, state2, sc, message_delta, false);
		if (ok)
			break;
	}
	if (!ok)
		return false;

	for (i = 0; i < 50000000; i ++)
	{
		tick(&tc, "block 1 - deep testing");

		ok = block1_amm(msg1, msg2, state1, state2, sc, message_delta, true);
		if (ok)
			return true;
	}

	return false;
}

void block1(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const uint32_t *const message_delta)
{
	tick_context tc;
	compiled_sufficient_cond sc[64];

	/* compile sufficient conditions into bitmasks */
	block1_fill_sc(sc);

	tick_init(&tc, 1000000);
	while (!block1_try(msg1, msg2, state1, state2, sc, message_delta))
		tick(&tc, "block 1 - random state");
}



void block2_fill_sc(compiled_sufficient_cond *sc)
{
	const sufficient_cond sc_raw[64] =
	{
		/* a1 */ {0x7e000000, "P---010- --1----- ----0--- --0-----"},
		/* d1 */ {0x7dffffe0, "pppp110- --0ppppp 0--p1--- pp0--00-"},
		/* c1 */ {0x7dfef7e0, "p011111- --011111 ---01--1 011pp11-"},
		/* b1 */ {0x7dffffe2, "p011101- --000100 ---00pp0 0001000p"},
		/* a2 */ {0x7ffffcbf, "P10010-- --101111 ---01110 01010000"},
		/* d2 */ {0x80110000, "p--0010- --10--10 ---01100 01010110"},
		/* c2 */ {0x88000040, "P--1011p p-00--01 p--11110 00-----1"},
		/* b2 */ {0x80818000, "p--00100 0-11--10 1-----11 11----p0"},
		/* a3 */ {0x7fffffbf, "p--11100 0-----01 0--p--01 11----01"},
		/* d3 */ {0x7ffff000, "p----111 1----011 1--0--11 11----00"},
		/* c3 */ {0x80000000, "p------- ----p101 1pp0--11 11----11"},
		/* b3 */ {0x80002080, "pppppppp ----1000 0001---- 1-------"},
		/* a4 */ {0x7f000000, "P-111111 ----1111 111----- 0---1---"},
		/* d4 */ {0x80000000, "p1000000 ----1011 111----- 1---1---"},
		/* c4 */ {0x7fff7ff8, "p1111101 -------- 0------- ----0---"},
		/* b4 */ {0xa0000000, "p-1----- -------- -------- --------"},
		/* a5 */ {0x80000000, "p------- ------0- p------- ----p---"},
		/* d5 */ {0x80000000, "p-p----- ------1- -------- --------"},
		/* c5 */ {0x7ffe0000, "p------- ------0- -------- --------"},
		/* b5 */ {0x80000000, "p------- -------- -------- --------"},
		/* a6 */ {0x80000000, "p------- ------p- -------- --------"},
		/* d6 */ {0x80000000, "p------- -------- -------- --------"},
		/* c6 */ {0x00000000, "p------- -------- -------- --------"},
		/* b6 */ {0x00000000, "P------- -------- -------- --------"},
		/* a7 */ {0x00000000, "-------- -------- -------- --------"},
		/* d7 */ {0x00000000, "-------- -------- -------- --------"},
		/* c7 */ {0x00000000, "-------- -------- -------- --------"},
		/* b7 */ {0x00000000, "-------- -------- -------- --------"},
		/* a8 */ {0x00000000, "-------- -------- -------- --------"},
		/* d8 */ {0x00000000, "-------- -------- -------- --------"},
		/* c8 */ {0x00000000, "-------- -------- -------- --------"},
		/* b8 */ {0x00000000, "-------- -------- -------- --------"},
		/* a9 */ {0x00000000, "-------- -------- -------- --------"},
		/* d9 */ {0x00000000, "-------- -------- -------- --------"},
		/* c9 */ {0x80000000, "-------- -------- -------- --------"},
		/* b9 */ {0x80000000, "-------- -------- -------- --------"},
		/* a10*/ {0x80000000, "-------- -------- -------- --------"},
		/* d10*/ {0x80000000, "-------- -------- -------- --------"},
		/* c10*/ {0x80000000, "-------- -------- -------- --------"},
		/* b10*/ {0x80000000, "-------- -------- -------- --------"},
		/* a11*/ {0x80000000, "-------- -------- -------- --------"},
		/* d11*/ {0x80000000, "-------- -------- -------- --------"},
		/* c11*/ {0x80000000, "-------- -------- -------- --------"},
		/* b11*/ {0x80000000, "-------- -------- -------- --------"},
		/* a12*/ {0x80000000, "-------- -------- -------- --------"},
		/* d12*/ {0x80000000, "-------- -------- -------- --------"},
		/* c12*/ {0x80000000, "-------- -------- -------- --------"},
		/* b12*/ {0x80000000, "f------- -------- -------- --------"},
		/* a13*/ {0x80000000, "f------- -------- -------- --------"},
		/* d13*/ {0x80000000, "F------- -------- -------- --------"},
		/* c13*/ {0x80000000, "f------- -------- -------- --------"},
		/* b13*/ {0x80000000, "f------- -------- -------- --------"},
		/* a14*/ {0x80000000, "f------- -------- -------- --------"},
		/* d14*/ {0x80000000, "f------- -------- -------- --------"},
		/* c14*/ {0x80000000, "f------- -------- -------- --------"},
		/* b14*/ {0x80000000, "f------- -------- -------- --------"},
		/* a15*/ {0x80000000, "f------- -------- -------- --------"},
		/* d15*/ {0x80000000, "f------- -------- -------- --------"},
		/* c15*/ {0x80000000, "f------- -------- -------- --------"},
		/* b15*/ {0x80000000, "F------- -------- -------- --------"},
		/* a16*/ {0x80000000, "f-----1- -------- -------- --------"}, /* checked manually */
		/* d16*/ {0x82000000, "f-----1- -------- -------- --------"}, /* checked manually */
		/* c16*/ {0x82000000, "f-----1- -------- -------- --------"}, /* checked manually */
		/* b16*/ {0x82000000, "------1- -------- -------- --------"}, /* checked manually */
	};

	compile_sc(sc_raw, sc, 64);
}

__attribute__((always_inline)) inline bool block2_amm(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const compiled_sufficient_cond *const sc,
	const uint32_t *const message_delta,
	bool full)
{
	size_t i;

	#if 1

	if (!full)
	{
		/* d1 */
		state1[1] = random();
		fix_sc(state1, state2, 1, sc);

		for (i = 1; i < 6; i ++)
		{
			recover_msg(msg1 + 16, msg2 + 16, state1, state2, i);
			if (!check_msg(msg1 + 16, msg2 + 16, i, message_delta))
				return false;
		}

		/* a5 */
		recover_state(msg1 + 16, msg2 + 16, state1, state2, 16);
		if (!check_sc(state1, state2, 16, sc))
			return false;
	}

	/* d2 */
	state1[6] = random();
	fix_sc(state1, state2, 6, sc);

	for (i = 6; i < 11; i ++)
	{
		recover_msg(msg1 + 16, msg2 + 16, state1, state2, i);
		if (!check_msg(msg1 + 16, msg2 + 16, i, message_delta))
			return false;
	}

	/* d5 */
	recover_state(msg1 + 16, msg2 + 16, state1, state2, 17);
	if (!check_sc(state1, state2, 17, sc))
		return false;

	/* b3 */
	state1[11] = random();
	fix_sc(state1, state2, 11, sc);

	for (i = 11; i < 16; i ++)
	{
		recover_msg(msg1 + 16, msg2 + 16, state1, state2, i);
		if (!check_msg(msg1 + 16, msg2 + 16, i, message_delta))
			return false;
	}

	/* c5 */
	recover_state(msg1 + 16, msg2 + 16, state1, state2, 18);
	if (!check_sc(state1, state2, 18, sc))
		return false;

	/* check round 2 and round 3 output differences */
	/* b5 to b6 (partial) or b5 to b15 (full)*/
	for (i = 19; i < (full ? 60 : 24); i ++)
	{
		recover_state(msg1 + 16, msg2 + 16, state1, state2, i);
		if (!check_sc(state1, state2, i, sc))
			return false;
	}

	#else

	state1[15] = random();
	fix_sc(state1, state2, 15, sc);

	recover_msg(msg1 + 16, msg2 + 16, state1, state2, 15);
	if (!check_msg(msg1 + 16, msg2 + 16, 15, message_delta))
		return false;

	/* check round 2 and round 3 output differences */
	/* a5 to a6 (partial) or a5 to b15 (full)*/
	for (i = 16; i < (full ? 60 : 21); i ++)
	{
		recover_state(msg1 + 16, msg2 + 16, state1, state2, i);
		if (!check_sc(state1, state2, i, sc))
			return false;
	}

	#endif

	/* check final SCs on a16 to b16 manually */
	if (full)
	{
		for (i = 60; i < 64; i ++)
			recover_state(msg1 + 16, msg2 + 16, state1, state2, i);

		for (i = 60; i < 64; i ++)
		{
			state1[i] += state1[i-64];
			state2[i] += state2[i-64];
		}

		for (i = 60; i < 64; i ++)
			if (state1[i] != state2[i])
				return false;

		for (i = 60; i < 64; i ++)
		{
			state1[i] -= state1[i-64];
			state2[i] -= state2[i-64];
		}
	}
	return true;
}

__attribute__((always_inline)) inline bool block2_try(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const compiled_sufficient_cond *sc,
	const uint32_t *const message_delta)
{
	tick_context tc;
	size_t i;
	bool ok;

	tick_init(&tc, 10000000);

	/* round 1 */
	/* a1 to c4 */
	for (i = 0; i < 16; i ++)
	{
		/* generate random state */
		state1[i] = random();

		/* do simple message modification */
		fix_sc(state1, state2, i, sc);
	}

	/* recover message words from internal state */
	for (i = 0; i < 16; i ++)
	{
		recover_msg(msg1 + 16, msg2 + 16, state1, state2, i);
		if (!check_msg(msg1 + 16, msg2 + 16, i, message_delta))
			return false;
	}

	/* deep testing */
	for (i = 0; i < 10000; i ++)
	{
		ok = block2_amm(msg1, msg2, state1, state2, sc, message_delta, false);
		if (ok)
			break;
	}
	if (!ok)
		return false;

	for (i = 0; i < 50000000; i ++)
	{
		tick(&tc, "block 2 - deep testing");

		ok = block2_amm(msg1, msg2, state1, state2, sc, message_delta, true);
		if (ok)
			return true;
	}

	return false;
}

void block2(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const uint32_t *const message_delta)
{
	tick_context tc;
	compiled_sufficient_cond sc[64];

	/* compile sufficient conditions into bitmasks */
	block2_fill_sc(sc);

	tick_init(&tc, 1000000);
	while (!block2_try(msg1, msg2, state1, state2, sc, message_delta))
		tick(&tc, "block 2 - random state");
}



void gen_collisions(uint32_t msg1[32], uint32_t msg2[32])
{
	size_t i;

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

	uint32_t state1real[68], state2real[68];
	uint32_t *state1, *state2;

	state1 = state1real + 4;
	state2 = state2real + 4;
	state1[-4] = state2[-4] = md5_iv[0];
	state1[-3] = state2[-3] = md5_iv[3];
	state1[-2] = state2[-2] = md5_iv[2];
	state1[-1] = state2[-1] = md5_iv[1];

	block1(msg1, msg2, state1, state2, message_delta);
	dump_state(msg1, msg2, 32, state1, state2, 64);

	for (i = 60; i < 64; i ++)
	{
		state1[i - 64] += state1[i];
		state2[i - 64] += state2[i];
	}

	block2(msg1, msg2, state1, state2, message_delta);
	dump_state(msg1, msg2, 32, state1, state2, 64);
}

int main(int argc, char *argv[])
{
	size_t i;
	uint32_t msg1[32], msg2[32];

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
