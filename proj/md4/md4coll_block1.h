#ifndef MD4COLL_BLOCK1_H
#define MD4COLL_BLOCK1_H
#include <stdint.h>

void block1(
	uint32_t *const msg1,
	uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const uint32_t *const message_delta);

#endif
