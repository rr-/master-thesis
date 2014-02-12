#include <stddef.h>
#include "md4.h"
#include "common.h"

uint32_t md4_f(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x&y) | ((~x)&z));
}

uint32_t md4_g(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) | (x&z) | (y&z);
}

uint32_t md4_h(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}

const uint32_t md4_iv[4] =
{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476
};

const uint32_t md4_shift[48] =
{
	/* round 1 */
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	3, 7, 11, 19,
	/* round 2 */
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	3, 5, 9, 13,
	/* round 3 */
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15,
	3, 9, 11, 15,
};

const uint32_t md4_msg_index[48] =
{
	/* round 1 */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	/* round 2 */ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	/* round 3 */ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
};

const uint32_t md4_add[48] =
{
	/* round 1 */
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	/* round 2 */
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	/* round 3 */
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
};

uint32_t (*md4_round_func[48])(uint32_t x, uint32_t y, uint32_t z) =
{
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_f, &md4_f, &md4_f, &md4_f,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_g, &md4_g, &md4_g, &md4_g,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
	&md4_h, &md4_h, &md4_h, &md4_h,
};

void recover_state(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const size_t i)
{
	state1[i] =
		rot_left(
			(*md4_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3])
				+ state1[i - 4]
				+ msg1[md4_msg_index[i]]
				+ md4_add[i],
			md4_shift[i]);

	state2[i] =
		rot_left(
			(*md4_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3])
				+ state2[i - 4]
				+ msg2[md4_msg_index[i]]
				+ md4_add[i],
			md4_shift[i]);
}
