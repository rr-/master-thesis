#include <stddef.h>
#include "md5.h"
#include "common.h"

uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z)
{
	return z^(x&(y^z));
}

uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z)
{
	return y^(z&(x^y));
}

uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}

uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z)
{
	return y^(x|~z);
}

const uint32_t md5_iv[4] =
{
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
};

const uint32_t md5_shift[64] =
{
	/* round 1 */
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	/* round 2 */
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	/* round 3 */
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	/* round 4 */
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
};

const uint32_t md5_msg_index[64] =
{
	/* round 1 */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	/* round 2 */ 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	/* round 3 */ 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	/* round 4 */ 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
};

const uint32_t md5_add[64] =
{
	/* round 1 */
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	/* round 2 */
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	/* round 3 */
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	/* round 4 */
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

uint32_t (*const md5_round_func[64])(
	uint32_t x,
	uint32_t y,
	uint32_t z) =
{
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_f, &md5_f, &md5_f, &md5_f,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_g, &md5_g, &md5_g, &md5_g,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_h, &md5_h, &md5_h, &md5_h,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
	&md5_i, &md5_i, &md5_i, &md5_i,
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
			(*md5_round_func[i])(state1[i - 1], state1[i - 2], state1[i - 3])
				+ state1[i - 4]
				+ msg1[md5_msg_index[i]]
				+ md5_add[i],
			md5_shift[i])
		+ state1[i - 1];

	state2[i] =
		rot_left(
			(*md5_round_func[i])(state2[i - 1], state2[i - 2], state2[i - 3])
				+ state2[i - 4]
				+ msg2[md5_msg_index[i]]
				+ md5_add[i],
			md5_shift[i])
		+ state2[i - 1];
}
