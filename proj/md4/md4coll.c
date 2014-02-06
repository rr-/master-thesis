#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include "sc.h"
#include "tick.h"

/* md4 stuff */

const uint32_t md4_iv[4] =
{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476
};

const uint32_t md4_shift[48] =
{
	/* round 1 */
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	/* round 2 */
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	/* round 3 */
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15,
};

const uint32_t md4_msg_index[48] =
{
	/* round 1 */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	/* round 2 */ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	/* round 3 */ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
};

const uint32_t md4_add[48] =
{
	/* round 1 */
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	/* round 2 */
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	/* round 3 */
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
};

uint32_t md4_f(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x&y) | ((~x)&z));
}

uint32_t md4_g(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) | (x&z) | (y&z);
}

uint32_t md4_h(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}

uint32_t (*md4_round_func[48])(uint32_t x, uint32_t y, uint32_t z) =
{
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
};


/* message delta as in wang's paper */
const uint32_t message_delta[16] =
{
	/* 0 */ 0,
	/* 1 */ (1 << 31),
	/* 2 */ (1 << 31) | (1 << 28),
	/* 3 */ 0,
	/* 4 */ 0,
	/* 5 */ 0,
	/* 6 */ 0,
	/* 7 */ 0,
	/* 8 */ 0,
	/* 9 */ 0,
	/* 10 */ 0,
	/* 11 */ 0,
	/* 12 */ 1 << 16,
	/* 13 */ 0,
	/* 14 */ 0,
	/* 15 */ 0,
};

/* prepare differences and bitmasks for sufficient conditions based on
 * human-readable table */
void fill_sc(compiled_sufficient_cond *sc)
{
	/* differences as in wang's paper */
	const sufficient_cond sc_raw[48] =
	{
		/* a1 */ {0x00000000, "-------- -------- -------- -p------"},
		/* d1 */ {0xffffffc0, "-------- -------- -----p-- p0------"},
		/* c1 */ {0xfffffc80, "------p- -------- -----0-- 11------"},
		/* b1 */ {0xfe000000, "------0- -------- -----0-- 01------"},
		/* a2 */ {0x00000000, "------0- -------- --p--1-- 1-------"},
		/* d2 */ {0xffffe000, "------1- --pppp-- --0----- --------"},
		/* c2 */ {0xffe40000, "-------- --0100-- -p0p---- --------"},
		/* b2 */ {0xfffff000, "-------- --0000-p -011---- --------"},
		/* a3 */ {0xffff0000, "------p- -p1000-0 -111---- --------"},
		/* d3 */ {0x01e80000, "--p---1- -0110--0 -111---- --------"},
		/* c3 */ {0x20000000, "p-1---0- -0000--1 -------- --------"},
		/* b3 */ {0x80000000, "0-0---1- -p110--- -------- --------"},
		/* a4 */ {0xfdc00000, "0-1p-p0- -0------ -------- --------"},
		/* d4 */ {0xf4000000, "1-01-10- -0------ -------- --------"},
		/* c4 */ {0x00000000, "--00-01- -1---p-- -------- --------"},
		/* b4 */ {0xfffc0000, "--01-11- -----0-- -------- --------"},
		/* a5 */ {0x8e000000, "1--1-01- -----f-- -------- --------"},
		/* d5 */ {0x00000000, "f--f-ff- -----p-- -------- --------"},
		/* c5 */ {0x00000000, "p-pp-pp- -------- -------- --------"},
		/* b5 */ {0xa0000000, "0-1p---- -------- -------- --------"},
		/* a6 */ {0x70000000, "1--1---- -------- -------- --------"},
		/* d6 */ {0x00000000, "---f---- -------- -------- --------"},
		/* c6 */ {0x00000000, "P-Pp---- -------- -------- --------"},
		/* b6 */ {0x00000000, "-------- -------- -------- --------"},
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
		/* c9 */ {0x00000000, "-------- -------- -------- --------"},
		/* b9 */ {0x80000000, "1------- -------- -------- --------"},
		/* a10*/ {0x80000000, "1------- -------- -------- --------"},
		/* d10*/ {0x00000000, "-------- -------- -------- --------"},
		/* c10*/ {0x00000000, "-------- -------- -------- --------"},
		/* b10*/ {0x00000000, "-------- -------- -------- --------"},
		/* a11*/ {0x00000000, "-------- -------- -------- --------"},
		/* d11*/ {0x00000000, "-------- -------- -------- --------"},
		/* c11*/ {0x00000000, "-------- -------- -------- --------"},
		/* b11*/ {0x00000000, "-------- -------- -------- --------"},
		/* a12*/ {0x00000000, "-------- -------- -------- --------"},
		/* d12*/ {0x00000000, "-------- -------- -------- --------"},
		/* c12*/ {0x00000000, "-------- -------- -------- --------"},
		/* b12*/ {0x00000000, "-------- -------- -------- --------"},
	};

	compile_sc(sc_raw, sc, 48);
}

void block1(uint32_t *msg1, uint32_t *msg2, uint32_t *state1, uint32_t *state2)
{
	bool ok;
	size_t i;
	tick_context tc;
	compiled_sufficient_cond sc[48];

	/* compile sufficient conditions into bitmasks */
	fill_sc(sc);

	tick_init(&tc);
	while (true)
	{
		ok = true;
		tick(&tc, NULL);

		/* round 1 */
		/* A1 to B4 */
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
			msg1[i] = rot_right(state1[i], md4_shift[i]) - (*md4_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) - md4_add[i] - state1[i - 4];
			msg2[i] = rot_right(state2[i], md4_shift[i]) - (*md4_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) - md4_add[i] - state2[i - 4];

			/* simple checks for message delta */
			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/* check round 2 and round  3 output differences */
		/* A5 to B12 */
		for (i = 16; i < 48; i ++)
		{
			state1[i] = rot_left((*md4_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md4_msg_index[i]] + md4_add[i], md4_shift[i]);
			state2[i] = rot_left((*md4_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md4_msg_index[i]] + md4_add[i], md4_shift[i]);

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

void gen_collisions(uint32_t msg1[16], uint32_t msg2[16])
{
	uint32_t state1real[52], state2real[52];
	uint32_t *state1, *state2;

	/*
		simple hack to conveniently make array indexing easier:
		arr[-1] <=> (arr+(-1))
	*/
	state1 = state1real + 4;
	state2 = state2real + 4;
	state1[-4] = state2[-4] = md4_iv[0]; /* A0 */
	state1[-3] = state2[-3] = md4_iv[3]; /* D0 */
	state1[-2] = state2[-2] = md4_iv[2]; /* C0 */
	state1[-1] = state2[-1] = md4_iv[1]; /* B0 */

	block1(msg1, msg2, state1, state2);
}

int main(void)
{
	size_t i;
	uint32_t msg1[16], msg2[16];

	srandom(time(NULL));
	gen_collisions(msg1, msg2);

	for (i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg1[i]));
	puts("");

	for (i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg2[i]));
	puts("");

	return 0;
}
