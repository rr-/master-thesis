#include <stddef.h>
#include "md4coll_block1.h"
#include "md4rev.h"
#include "md4.h"
#include "sc.h"
#include "common.h"
#include "tick.h"

/* prepare differences and bitmasks for sufficient conditions based on
 * human-readable table */
void block1_fill_sc(compiled_sufficient_cond *const sc)
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

	/* simplify advanced message modification */
	/* keep randomizing first state. */
	state1[0] = random();
	state1[0] &= (~0x480);
	state1[0] |= (state1[1] & 0x480);
	fix_sc(state1, state2, 0, sc);

	/* recover message words from internal state */
	for (i = 0; i < 5; i ++)
	{
		recover_msg(msg1, msg2, state1, state2, i);
		if (!check_msg(msg1, msg2, i, message_delta))
			return false;
	}

	/* check round 2 and round 3 output differences */
	/* a5 to b5 (partial) or a5 to b12 (full) */
	for (i = 16; i < (full ? 48 : 20); i ++)
	{
		recover_state(msg1, msg2, state1, state2, i);
		if (!check_sc(state1, state2, i, sc))
			return false;
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

	tick_init(&tc, 1000000);

	/* round 1 */
	/* b1 to b4 */
	for (i = 1; i < 16; i ++)
	{
		/* generate random state */
		state1[i] = random();

		/* do simple message modification */
		fix_sc(state1, state2, i, sc);
	}

	/*
		recover message words from internal state, but only those that
		can be recovered = words 5..15. message words 0..4 are going to
		use state1[0], which is later randomized.
	*/
	for (i = 5; i < 16; i ++)
	{
		recover_msg(msg1, msg2, state1, state2, i);
		if (!check_msg(msg1, msg2, i, message_delta))
			return false;
	}

	/*
		poke around trying to guess a1 and see if it passes
		sufficient conditions for a5..b5.
		basically, it's simplification of first advanced message
		modification technique proposed by Wang et al., that still
		gives great probability for attack to succeed.
	*/
	for (i = 0; i < 100; i ++)
	{
		ok = block1_amm(msg1, msg2, state1, state2, sc, message_delta, false);
		if (ok)
			break;
	}
	if (!ok)
		return false;

	/*
		if we get here, it means that current set of state1[1..15] is
		likely to pass full test upon good selection of state1[0].
		try harder to look for good modification.
	*/
	for (i = 0; i < 5000000; i ++)
	{
		tick(&tc, "deep testing");

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

	compiled_sufficient_cond sc[48];
	block1_fill_sc(sc);

	tick_init(&tc, 1000);
	while (!block1_try(msg1, msg2, state1, state2, sc, message_delta))
		tick(&tc, "random state");
}
