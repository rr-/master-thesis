#ifndef MD5REV_H
#define MD5REV_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* message delta as in wang's paper */
extern const uint32_t message_delta[16];

void recover_msg(
	uint32_t *const msg1,
	uint32_t *const msg2,
	const uint32_t *const state1,
	const uint32_t *const state2,
	const size_t i);

bool check_msg(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	const size_t i,
	const uint32_t *const message_delta);

#endif
