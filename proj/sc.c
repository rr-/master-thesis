#include <string.h>
#include <stdio.h>
#include "sc.h"
#include "common.h"

bool check_sc(
	const uint32_t *const state1,
	const uint32_t *const state2,
	size_t i,
	const compiled_sufficient_cond *const sc)
{
	uint32_t diff1, diff2;

	if ((state1[i] - state2[i]) != sc[i].diff)
		return false;

	if (sc[i].fast_quit)
		return true;

	if (state1[i] & sc[i].zero)
		return false;

	if ((state1[i] & sc[i].one) != sc[i].one)
		return false;


	diff1 = state1[i] ^ state1[i - 1];
	if (diff1 & sc[i].prev1)
		return false;

	if ((diff1 & sc[i].prev1neg) != sc[i].prev1neg)
		return false;


	diff2 = state1[i] ^ state1[i - 2];
	if (diff2 & sc[i].prev2)
		return false;

	if ((diff2 & sc[i].prev2neg) != sc[i].prev2neg)
		return false;

	return true;
}

void fix_sc(
	uint32_t *const state1,
	uint32_t *const state2,
	size_t i,
	const compiled_sufficient_cond *const sc)
{
	if (sc[i].fast_quit)
		return;

	state1[i] |= sc[i].one;

	state1[i] &= ~sc[i].zero;

	state1[i] &= ~sc[i].prev1;
	state1[i] |= (state1[i - 1] & sc[i].prev1);

	state1[i] &= ~sc[i].prev1neg;
	state1[i] |= ((~state1[i - 1]) & sc[i].prev1neg);

	state1[i] &= ~sc[i].prev2;
	state1[i] |= (state1[i - 2] & sc[i].prev2);

	state1[i] &= ~sc[i].prev2neg;
	state1[i] |= ((~state1[i - 2]) & sc[i].prev2neg);

	state2[i] = state1[i] - sc[i].diff;
}

void compile_sc(
	const sufficient_cond *const sc_comp,
	compiled_sufficient_cond *const sc,
	size_t max)
{
	size_t i, j, bit;
	char c;
	uint32_t *dest;

	for (i = 0; i < max; i ++)
	{
		sc[i].one = 0;
		sc[i].zero = 0;
		sc[i].prev1 = 0;
		sc[i].prev2 = 0;
		sc[i].prev1neg = 0;
		sc[i].prev2neg = 0;
		sc[i].fast_quit = true;
		sc[i].diff = sc_comp[i].diff;

		bit = 31;
		/* read left-to-right, starting with 31th bit, end with 0th bit */
		for (j = 0; j < strlen(sc_comp[i].str); j ++)
		{
			c = sc_comp[i].str[j];
			if (c == ' ') /* ignore spaces */
				continue;

			dest = NULL;
			if (c == '1')
				dest = &sc[i].one;
			else if (c == '0')
				dest = &sc[i].zero;
			else if (c == 'p')
				dest = &sc[i].prev1;
			else if (c == 'P')
				dest = &sc[i].prev1neg;
			else if (c == 'f')
				dest = &sc[i].prev2;
			else if (c == 'F')
				dest = &sc[i].prev2neg;
			if (dest != NULL)
			{
				*dest |= (1 << bit);
				sc[i].fast_quit = false;
			}

			-- bit;
		}
	}
}

void dump_state(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	size_t const msg_count,
	const uint32_t *const state1,
	const uint32_t *const state2,
	size_t const state_count)
{
	size_t i;
	for (i = 0; i < state_count; i ++)
	{
		fprintf(stderr,
			"state1[%2d]=0x%08x; state2[%2d]=0x%08x; ",
			i, to_big_endian(state1[i]),
			i, to_big_endian(state2[i]));

		if (i % 4 == 3)
			fprintf(stderr, "\n");
	}

	for (i = 0; i < msg_count; i ++)
	{
		fprintf(stderr,
			"msg1[%2d]=0x%08x; msg2[%2d]=0x%08x; ",
			i, to_big_endian(msg1[i]),
			i, to_big_endian(msg2[i]));

		if (i % 4 == 3)
			fprintf(stderr, "\n");
	}
}
