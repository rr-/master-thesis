#include <stddef.h>
#include "md5coll_block2.h"
#include "md5rev.h"
#include "md5.h"
#include "common.h"
#include "tick.h"
#include "sc.h"

/* prepare differences and bitmasks for sufficient conditions based on
 * human-readable table */
void block2_fill_sc(compiled_sufficient_cond *const sc)
{
	/* differences and sufficient conditions as in wang's paper */
	const sufficient_cond sc_raw[64] =
	{
		/* a1 */ {0x7e000000, "P---010- --1----1 ----0--- --0-----"},
		/* d1 */ {0x7dffffe0, "pppp110- --0pppp1 0--p1--- pp0--00-"},
		/* c1 */ {0x7dfef7e0, "p011111- --011111 1--01--1 011pp111"},
		/* b1 */ {0x7dffffe2, "p011101- --000100 ---00pp0 00010001"},
		/* a2 */ {0x7ffffcbf, "P10010-- --101111 ---01110 01010000"},
		/* d2 */ {0x80110000, "p--0010- --10--10 -1-01100 01010110"},
		/* c2 */ {0x88000040, "P--1011p p-00--01 p0-11110 00-----1"},
		/* b2 */ {0x80818000, "p--00100 0-11--10 1-----11 111---p0"},
		/* a3 */ {0x7fffffbf, "p--11100 0-----01 0--p--01 110---01"},
		/* d3 */ {0x7ffff000, "p----111 1----011 1--01-11 11----00"},
		/* c3 */ {0x80000000, "p------- ----p101 1pp00-11 11----11"},
		/* b3 */ {0x80002080, "pppppppp ----1000 0001---- 1-------"},
		/* a4 */ {0x7f000000, "P0111111 0---1111 111----- 0---1---"},
		/* d4 */ {0x80000000, "p1000000 1---1011 111----- 1---1---"},
		/* c4 */ {0x7fff7ff8, "-1111101 -------0 0------- ----0---"},
		/* b4 */ {0xa0000000, "p-10---- -------1 1------- ----1---"},
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
	const compiled_sufficient_cond *const sc,
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
