#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

/*md4 stuff*/

const uint32_t md4_iv[4] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476
};

const uint32_t md4_shift[48] = {
	/*round 1*/
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	/*round 2*/
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	/*round 3*/
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15
};

const uint32_t md4_msg_index[48] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, /*round 1*/
	0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, /*round 2*/
	0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15, /*round 3*/
};

const uint32_t md4_add[3] = {
	0x00000000,
	0x5a827999,
	0x6ed9eba1
};

uint32_t md4_f(uint32_t x, uint32_t y, uint32_t z) { return ((x&y) | ((~x)&z)); }
uint32_t md4_g(uint32_t x, uint32_t y, uint32_t z) { return (x&y) | (x&z) | (y&z); }
uint32_t md4_h(uint32_t x, uint32_t y, uint32_t z) { return x^y^z; }



/*prepare bitmasks for sufficient conditions based on human-readable table*/
void fill_sufficient_conditions(
	uint32_t sc_zero[48],
	uint32_t sc_one[48],
	uint32_t sc_prev1[48],
	uint32_t sc_prev2[48])
{
	size_t i, j;
	size_t bit;
	char c;
	uint32_t *dest;

	/*
		sufficient conditions for each chaining variable.
		0 - must be 0
		1 - must be 0
		p - must be same as in previous round
		P - must be different from previoud round
		f - must be same as in second previous round
	*/
	const char *sufficient_conditions[] =
	{
		/* a1 */ "-------- -------- -------- -p------",
		/* d1 */ "-------- -------- -----p-- p0------",
		/* c1 */ "------p- -------- -----0-- 11------",
		/* b1 */ "------0- -------- -----0-- 01------",
		/* a2 */ "------0- -------- --p--1-- 1-------",
		/* d2 */ "------1- --pppp-- --0----- --------",
		/* c2 */ "-------- --0100-- -p0p---- --------",
		/* b2 */ "-------- --0000-p -011---- --------",
		/* a3 */ "------p- -p1000-0 -111---- --------",
		/* d3 */ "--p---1- -0110--0 -111---- --------",
		/* c3 */ "p-1---0- -0000--1 -------- --------",
		/* b3 */ "0-0---1- -p110--- -------- --------",
		/* a4 */ "0-1p-p0- -0------ -------- --------",
		/* d4 */ "1-01-10- -0------ -------- --------",
		/* c4 */ "--00-01- -1---p-- -------- --------",
		/* b4 */ "--01-11- -----0-- -------- --------", /*p-01-11- -----0-- -------- -------- naito et al.*/
		/* a5 */ "1--1-01- -----f-- -------- --------",
		/* d5 */ "f--f-ff- -----p-- -------- --------",
		/* c5 */ "p-pp-pp- -------- -------- --------",
		/* b5 */ "0-1p---- -------- -------- --------",
		/* a6 */ "1--1---- -------- -------- --------", /*1-01---- -------- -------- -------- naito et al.*/
		/* d6 */ "---f---- -------- -------- --------",
		/* c6 */ "P-Pp---- -------- -------- --------",
		/* b6 */ "-------- -------- -------- --------",
		/* a7 */ "-------- -------- -------- --------",
		/* d7 */ "-------- -------- -------- --------",
		/* c7 */ "-------- -------- -------- --------",
		/* b7 */ "-------- -------- -------- --------",
		/* a8 */ "-------- -------- -------- --------",
		/* d8 */ "-------- -------- -------- --------",
		/* c8 */ "-------- -------- -------- --------",
		/* b8 */ "-------- -------- -------- --------",
		/* a9 */ "-------- -------- -------- --------",
		/* d9 */ "-------- -------- -------- --------",
		/* c9 */ "-------- -------- -------- --------",
		/* b9 */ "1------- -------- -------- --------",
		/* a10*/ "1------- -------- -------- --------",
		/* d10*/ "-------- -------- -------- --------",
		/* c10*/ "-------- -------- -------- --------",
		/* b10*/ "-------- -------- -------- --------",
		/* a11*/ "-------- -------- -------- --------",
		/* d11*/ "-------- -------- -------- --------",
		/* c11*/ "-------- -------- -------- --------",
		/* b11*/ "-------- -------- -------- --------",
		/* a12*/ "-------- -------- -------- --------",
		/* d12*/ "-------- -------- -------- --------",
		/* c12*/ "-------- -------- -------- --------",
		/* b12*/ "-------- -------- -------- --------",
	};

	for (i = 0; i < 48; i ++)
	{
		sc_one[i] = 0;
		sc_zero[i] = 0;
		sc_prev1[i] = 0;
		sc_prev2[i] = 0;
		bit = 31;
		/*read left-to-right, starting with 31th bit, end with 0th bit*/
		for (j = 0; j < strlen(sufficient_conditions[i]); j ++)
		{
			c = sufficient_conditions[i][j];
			if (c == ' ') /*ignore spaces*/
				continue;

			dest = NULL;
			if (c == '1')
				dest = &sc_one[i];
			else if (c == '0')
				dest = &sc_zero[i];
			else if (c == 'p')
				dest = &sc_prev1[i];
			else if (c == 'f')
				dest = &sc_prev2[i];
			if (dest != NULL)
				*dest |= (1 << bit);

			-- bit;
		}
	}
}



void gen_collisions(uint32_t msg1[16], uint32_t msg2[16])
{
	size_t i;
	size_t attempts;
	bool ok;

	uint32_t state1real[52], state2real[52];
	uint32_t *state1, *state2;

	/*message delta as in wang's paper*/
	const uint32_t message_delta[16] = {
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

	/*differences as in wang's paper*/
	const uint32_t differences[48] = {
		/* a1 */ 0,
		/* d1 */ 0xffffffc0, /*2^6*/
		/* c1 */ 0xfffffc80, /*-2^7 + 2^10*/
		/* b1 */ 0xfe000000, /*2^25*/
		/* a2 */ 0,
		/* d2 */ 0xffffe000, /*2^13*/
		/* c2 */ 0xffe40000, /*-2^18 + 2^21*/
		/* b2 */ 0xfffff000, /*2^12*/
		/* a3 */ 0xffff0000, /*2^16*/
		/* d3 */ 0x01e80000, /*2^19 + 2^20 - 2^25*/
		/* c3 */ (1 << 29), /*-2^29*/
		/* b3 */ (1 << 31), /*2^31*/
		/* a4 */ 0xfdc00000, /*2^22 + 2^25*/
		/* d4 */ 0xf4000000, /*-2^26 + 2^28*/
		/* c4 */ 0,
		/* b4 */ 0xfffc0000, /*2^18*/
		/* a5 */ ((1 << 25) | (1 << 26) | (1 << 27) | (1 << 31)), /*2^25 - 2^28 - 2^31*/
		/* d5 */ 0,
		/* c5 */ 0,
		/* b5 */ ((1 << 29) | (1 << 31)), /*-2^29 + 2^31*/
		/* a6 */ ((1 << 28) | (1 << 29) | (1 << 30)), /*2^28 - 2^31*/
		/* d6 */ 0,
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
		/* c9 */ 0,
		/* b9 */ (1 << 31), /*2^31*/
		/* a10*/ (1 << 31), /*2^31*/
		/* d10*/ 0,
		/* c10*/ 0,
		/* b10*/ 0,
		/* a11*/ 0,
		/* d11*/ 0,
		/* c11*/ 0,
		/* b11*/ 0,
		/* a12*/ 0,
		/* d12*/ 0,
		/* c12*/ 0,
		/* b12*/ 0,
	};

	uint32_t sc_zero[48];
	uint32_t sc_one[48];
	uint32_t sc_prev1[48];
	uint32_t sc_prev2[48];

	/*
		simple hack to conveniently make array indexing easier:
		arr[-1] <=> (arr+(-1))
	*/
	state1 = state1real+4;
	state2 = state2real+4;
	state1[-4] = state2[-4] = md4_iv[0]; /* A0 */
	state1[-3] = state2[-3] = md4_iv[3]; /* D0 */
	state1[-2] = state2[-2] = md4_iv[2]; /* C0 */
	state1[-1] = state2[-1] = md4_iv[1]; /* B0 */

	/*compile sufficient conditions into bitmasks*/
	fill_sufficient_conditions(sc_zero, sc_one, sc_prev1, sc_prev2);

	attempts = 0;
	while (true)
	{
		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt %d\n", attempts);

		/*round 1*/
		for (i = 0; i < 16; i ++)
		{
			/*generate random state*/
			state1[i] = random();

			/*do simple message modification*/
			state1[i] |= sc_one[i];
			state1[i] &= ~sc_zero[i];
			if (sc_prev1[i])
			{
				state1[i] &= ~sc_prev1[i];
				state1[i] |= (state1[i-1] & sc_prev1[i]);
			}
			if (sc_prev2[i])
			{
				state1[i] &= ~sc_prev2[i];
				state1[i] |= (state1[i-1] & sc_prev2[i]);
			}

			/*prepare second state*/
			state2[i] = state1[i] - differences[i];
		}

		/*recover messages from internal state*/
		ok = true;
		for (i = 0; i < 16; i ++)
		{
			msg1[i] = rot_right(state1[i], md4_shift[i]) - md4_f(state1[i - 1], state1[i - 2], state1[i - 3]) - md4_add[0] - state1[i - 4];
			msg2[i] = rot_right(state2[i], md4_shift[i]) - md4_f(state2[i - 1], state2[i - 2], state2[i - 3]) - md4_add[0] - state2[i - 4];
			/*simple checks for message delta*/
			if ((msg1[i] ^ msg2[i]) != message_delta[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/*check round 2 output differences*/
		for (i = 16; i < 32; i ++)
		{
			state1[i] = rot_left(md4_g(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md4_msg_index[i]] + md4_add[1], md4_shift[i]);
			state2[i] = rot_left(md4_g(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md4_msg_index[i]] + md4_add[1], md4_shift[i]);
			if ((state1[i] - state2[i]) != differences[i])
			{
				ok = false;
				break;
			}
		}
		if (!ok)
			continue;

		/*check round 3 output differences*/
		for (i = 32; i < 48; i ++)
		{
			state1[i] = rot_left(md4_h(state1[i - 1], state1[i - 2], state1[i - 3]) + state1[i - 4] + msg1[md4_msg_index[i]] + md4_add[2], md4_shift[i]);
			state2[i] = rot_left(md4_h(state2[i - 1], state2[i - 2], state2[i - 3]) + state2[i - 4] + msg2[md4_msg_index[i]] + md4_add[2], md4_shift[i]);
			if ((state1[i] - state2[i]) != differences[i])
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

int main(void)
{
	size_t i;
	uint32_t msg1[16], msg2[16];

	srandom(time(NULL));
	gen_collisions(msg1, msg2);

	for(i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg1[i]));
	puts("");

	for(i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg2[i]));
	puts("");

	return 0;
}
