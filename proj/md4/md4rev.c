#include "md4rev.h"
#include "md4.h"
#include "common.h"

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

void recover_msg(
	uint32_t *const msg1,
	uint32_t *const msg2,
	const uint32_t *const state1,
	const uint32_t *const state2,
	const size_t i)
{
	msg1[i] = rot_right(state1[i], md4_shift[i])
		- (*md4_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3])
		- md4_add[i]
		- state1[i - 4];

	msg2[i] = rot_right(state2[i], md4_shift[i])
		- (*md4_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3])
		- md4_add[i]
		- state2[i - 4];
}

bool check_msg(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	const size_t i,
	const uint32_t *const message_delta)
{
	return (msg1[i] ^ msg2[i]) == message_delta[i];
}
