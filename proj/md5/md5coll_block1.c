#include <stddef.h>
#include "md5coll_block1.h"
#include "md5rev.h"
#include "md5.h"
#include "sc.h"
#include "common.h"
#include "tick.h"

/* prepare differences and bitmasks for sufficient conditions based on
 * human-readable table */
void block1_fill_sc(compiled_sufficient_cond *const sc)
{
	/* differences and sufficient conditions as in wang's paper */
	const sufficient_cond sc_raw[64 + 4] =
	{
		/* a1 */ {0x00000000, "-------- -------- -------- --------"},
		/* d1 */ {0x00000000, "-------- -------- -------- --------"},
		/* c1 */ {0x00000000, "-------- 0------- ----0--- -0------"},
		/* b1 */ {0x00000000, "1------- 0ppp1ppp pppp1ppp p011----"},
		/* a2 */ {0x00000040, "1000100- 01000000 00000000 0010-1-1"},
		/* d2 */ {0x7f800040, "0ppp0p1p 01111111 10111100 010pp0p1"},
		/* c2 */ {0x07800041, "00000011 11111110 11111000 00100000"},
		/* b2 */ {0x00827fff, "00000001 1--10001 0-0-0101 01000000"},
		/* a3 */ {0x8000003f, "11111011 ---10000 0-1p1111 00111101"},
		/* d3 */ {0x7ffff000, "0111---- 0--11111 1-01---0 01----00"},
		/* c3 */ {0x40000000, "0010---- ----0001 1p00---0 11----10"},
		/* b3 */ {0x80002080, "000---pp ----1000 0001---1 0-------"},
		/* a4 */ {0x7f000000, "01----01 ----1111 111----0 0---1---"},
		/* d4 */ {0x80000000, "000---00 ----1011 111----1 1---1---"},
		/* c4 */ {0x80007ff8, "-11---01 -------- 10------ ----0---"},
		/* b4 */ {0xa0000000, "p01----- --P----- -------- --------"},
		/* a5 */ {0x80000000, "p1------ ------0- p------- ----p---"},
		/* d5 */ {0x80000000, "p-p----- ------1- -------- --------"},
		/* c5 */ {0x7ffe0000, "p------- ------0- -------- --------"},
		/* b5 */ {0x80000000, "p------- -------- -------- --------"},
		/* a6 */ {0x80000000, "-------- ------p- -------- --------"},
		/* d6 */ {0x80000000, "p------- -------- -------- --------"},
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
		/* a16*/ {0x80000000, "f-----1- -------- -------- --------"},
		/* d16*/ {0x7e000000, "f------- -------- -------- --------"},
		/* c16*/ {0x7e000000, "-------- -------- -------- --------"},
		/* b16*/ {0x7e000000, "-------- -------- -------- --------"},
		/* aa0*/ {0x80000000, "-------- -------- -------- --------"},
		/* dd0*/ {0x7e000000, "------0- -------- -------- --------"},
		/* cc0*/ {0x7e000000, "p----01- -------- -------- --------"},
		/* bb0*/ {0x7e000000, "p----00- -------- -------- --0-----"},
	};

	compile_sc(sc_raw, sc, 64 + 4);
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
	for (i = 20; i < (full ? 64 : 27); i ++)
	{
		recover_state(msg1, msg2, state1, state2, i);
		if (!check_sc(state1, state2, i, sc))
			return false;
	}

	/* check final SCs on aa0 to bb0 manually */
	if (full)
	{
		for (i = 60; i < 64; i ++)
		{
			state1[i] += state1[i-64];
			state2[i] += state2[i-64];
		}

		for (i = 60; i < 64; i ++)
		{
			if (!check_sc(state1, state2, i, sc + 4))
				return false;
		}

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
	compiled_sufficient_cond sc[68];

	/* compile sufficient conditions into bitmasks */
	block1_fill_sc(sc);

	tick_init(&tc, 1000000);
	while (!block1_try(msg1, msg2, state1, state2, sc, message_delta))
		tick(&tc, "block 1 - random state");
}
