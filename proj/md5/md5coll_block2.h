#ifndef MD5COLL_BLOCK2_H
#define MD5COLL_BLOCK2_H
#include <stdint.h>

void block2(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const uint32_t *const message_delta);

#endif
