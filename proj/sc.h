#ifndef SC_H
#define SC_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct
{
	uint32_t diff;
	/*
		sufficient conditions for each chaining variable.
		0 - must be 0
		1 - must be 1
		p - must be same as in previous round
		f - must be same as in second previous round
		P - must be same different to previous round
		F - must be same different to second previous round
	*/
	const char *str;
} sufficient_cond;

typedef struct
{
	uint32_t diff;
	uint32_t zero;
	uint32_t one;
	uint32_t prev1;
	uint32_t prev1neg;
	uint32_t prev2;
	uint32_t prev2neg;
	uint32_t zero_all;

	bool fast_quit;
} compiled_sufficient_cond;

bool check_sc(
	const uint32_t *const state1,
	const uint32_t *const state2,
	size_t i,
	const compiled_sufficient_cond *const sc);

void fix_sc(
	uint32_t *const state1,
	uint32_t *const state2,
	size_t i,
	const compiled_sufficient_cond *const sc);

void compile_sc(
	const sufficient_cond *const sc_comp,
	compiled_sufficient_cond *const sc,
	size_t max);

void dump_state(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	size_t const msg_count,
	const uint32_t *const state1,
	const uint32_t *const state2,
	size_t const state_count);

#endif
