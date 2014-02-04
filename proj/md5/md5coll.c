#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "common.h"

/*md5 stuff*/

const uint32_t md5_iv[4] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
};

const uint32_t md5_add[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) { return z^(x&(y^z)); }
uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) { return y^(z&(x^y)); }
uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) { return x^y^z; }
uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) { return y^(x|~z); }



uint32_t randoms[40];
uint32_t myrandom(size_t index)
{
	return randoms[index];
}

void block1(
	uint32_t *msg1,
	uint32_t *msg2,
	uint32_t *state1,
	uint32_t *state2)
{
	size_t attempts = 0;

	for(;;)
	{
		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (1) %d\n", attempts);

		/* C1 */
		state1[3] = myrandom(0) & ~0x00800040;
		state2[3] = state1[3];

		/* B1 */
		state1[4] = (myrandom(1) | 0x80080800) & ~(0x00800040 | 0x0077f780);
		state1[4] |= (state1[3] & 0x0077f780);
		state2[4] = state1[4];

		/* A2 */
		state1[5] = (myrandom(2) | 0x88400025) & ~0x02bfffc0;
		state2[5] = state1[5] - 0x00000040;

		/* D2 */
		state1[6] = (myrandom(3) | 0x027fbc41) & ~(0x888043a4 | 0x7500001a);
		state1[6] |= (state1[5] & 0x7500001a);
		state2[6] = state1[6] - 0x7f800040;

		/* C2 */
		state1[7] = (myrandom(4) | 0x03fef820) & ~0xfc0107df;
		state2[7] = state1[7] - 0x07800041;

		msg1[6] = rot_right(state1[7] - state1[6], 17) - md5_f(state1[6], state1[5], state1[4]) - state1[3] - md5_add[6];
		msg2[6] = rot_right(state2[7] - state2[6], 17) - md5_f(state2[6], state2[5], state2[4]) - state2[3] - md5_add[6];
		if(msg1[6] != msg2[6])
			continue;

		/* B2 */
		state1[8] = (myrandom(5) | 0x01910540) & ~0xfe0eaabf;
		state2[8] = state1[8] - 0x00827fff;

		msg1[7] = rot_right(state1[8] - state1[7], 22) - md5_f(state1[7], state1[6], state1[5]) - state1[4] - md5_add[7];
		msg2[7] = rot_right(state2[8] - state2[7], 22) - md5_f(state2[7], state2[6], state2[5]) - state2[4] - md5_add[7];
		if(msg1[7] != msg2[7])
			continue;

		/* A3 */
		state1[9] = (myrandom(6) | 0xfb102f3d) & ~(0x040f80c2 | 0x00001000);
		state1[9] |= (state1[8] & 0x00001000);
		state2[9] = state1[9] - 0x8000003f;

		msg1[8] = rot_right(state1[9] - state1[8], 7) - md5_f(state1[8], state1[7], state1[6]) - state1[5] - md5_add[8];
		msg2[8] = rot_right(state2[9] - state2[8], 7) - md5_f(state2[8], state2[7], state2[6]) - state2[5] - md5_add[8];
		if(msg1[8] != msg2[8])
			continue;

		/* D3 */
		state1[10] = (myrandom(7) | 0x401f9040) & ~0x80802183;
		state2[10] = state1[10] - 0x7ffff000;

		msg1[9] = rot_right(state1[10] - state1[9], 12) - md5_f(state1[9], state1[8], state1[7]) - state1[6] - md5_add[9];
		msg2[9] = rot_right(state2[10] - state2[9], 12) - md5_f(state2[9], state2[8], state2[7]) - state2[6] - md5_add[9];
		if(msg1[9] != msg2[9])
			continue;

		/* C3 */
		state1[11] = (myrandom(8) | 0x000180c2) & ~(0xc00e3101 | 0x00004000);
		state1[11] |= (state1[10] & 0x00004000);
		state2[11] = state1[11] - 0x40000000;

		msg1[10] = rot_right(state1[11] - state1[10], 17) - md5_f(state1[10], state1[9], state1[8]) - state1[7] - md5_add[10];
		msg2[10] = rot_right(state2[11] - state2[10], 17) - md5_f(state2[10], state2[9], state2[8]) - state2[7] - md5_add[10];
		if(msg1[10] != msg2[10])
			continue;

		/* B3 */
		state1[12] = (myrandom(9) | 0x00081100) & ~(0xc007e080 | 0x03000000);
		state1[12] |= (state1[11] & 0x03000000);
		state2[12] = state1[12] - 0x80002080;

		msg1[11] = rot_right(state1[12] - state1[11], 22) - md5_f(state1[11], state1[10], state1[9]) - state1[8] - md5_add[11];
		msg2[11] = rot_right(state2[12] - state2[11], 22) - md5_f(state2[11], state2[10], state2[9]) - state2[8] - md5_add[11];
		if((msg1[11] ^ msg2[11]) != 0x00008000)
			continue;

		/* A4 */
		state1[13] = (myrandom(10) | 0x410fe008) & ~0x82000180;
		state2[13] = state1[13] - 0x7f000000;

		msg1[12] = rot_right(state1[13] - state1[12], 7) - md5_f(state1[12], state1[11], state1[10]) - state1[9] - md5_add[12];
		msg2[12] = rot_right(state2[13] - state2[12], 7) - md5_f(state2[12], state2[11], state2[10]) - state2[9] - md5_add[12];
		if(msg1[12] != msg2[12])
			continue;

		/* D4 */
		state1[14] = (myrandom(11) | 0x000be188) & ~0xa3040000;
		state2[14] = state1[14] - 0x80000000;

		msg1[13] = rot_right(state1[14] - state1[13], 12) - md5_f(state1[13], state1[12], state1[11]) - state1[10] - md5_add[13];
		msg2[13] = rot_right(state2[14] - state2[13], 12) - md5_f(state2[13], state2[12], state2[11]) - state2[10] - md5_add[13];
		if(msg1[13] != msg2[13])
			continue;

		/* C4 */
		state1[15] = (myrandom(12) | 0x21008000) & ~0x82000008;
		state2[15] = state1[15] - 0x80007ff8;

		msg1[14] = rot_right(state1[15] - state1[14], 17) - md5_f(state1[14], state1[13], state1[12]) - state1[11] - md5_add[14];
		msg2[14] = rot_right(state2[15] - state2[14], 17) - md5_f(state2[14], state2[13], state2[12]) - state2[11] - md5_add[14];
		if((msg1[14] ^ msg2[14]) != 0x80000000)
			continue;

		/* B4 */
		state1[16] = (myrandom(13) | 0x20000000) & ~0x80000000;
		state2[16] = state1[16] - 0xa0000000;

		msg1[15] = rot_right(state1[16] - state1[15], 22) - md5_f(state1[15], state1[14], state1[13]) - state1[12] - md5_add[15];
		msg2[15] = rot_right(state2[16] - state2[15], 22) - md5_f(state2[15], state2[14], state2[13]) - state2[12] - md5_add[15];
		if(msg1[15] != msg2[15])
			continue;

		/* A5 */
		state1[17] = myrandom(14) & ~(0x80020000 | 0x00008008);
		state1[17] |= (state1[16] & 0x00008008);
		state2[17] = state1[17] - 0x80000000;

		msg1[1] = rot_right(state1[17] - state1[16], 5) - md5_g(state1[16], state1[15], state1[14]) - state1[13] - md5_add[16];
		msg2[1] = rot_right(state2[17] - state2[16], 5) - md5_g(state2[16], state2[15], state2[14]) - state2[13] - md5_add[16];
		if(msg1[1] != msg2[1])
			continue;

		/* D5 */
		state1[18] = rot_left(md5_g(state1[17], state1[16], state1[15]) + state1[14] + msg1[6] + md5_add[17], 9) + state1[17];
		state2[18] = rot_left(md5_g(state2[17], state2[16], state2[15]) + state2[14] + msg2[6] + md5_add[17], 9) + state2[17];
		if((state1[18] & 0xa0020000) != (0x00020000 | (state1[17] & 0x20000000)))
			continue;
		if((state1[18] ^ state2[18]) != 0x80000000)
			continue;

		/* C5 */
		state1[19] = rot_left(md5_g(state1[18], state1[17], state1[16]) + state1[15] + msg1[11] + md5_add[18], 14) + state1[18];
		state2[19] = rot_left(md5_g(state2[18], state2[17], state2[16]) + state2[15] + msg2[11] + md5_add[18], 14) + state2[18];
		if(state1[19] & 0x80020000)
			continue;
		if(state1[19] - state2[19] != 0x7ffe0000)
			continue;

		/* B5 */
		state1[20] = myrandom(16);
		state2[20] = state1[20] - 0x80000000;

		msg1[0] = rot_right(state1[20] - state1[19], 20) - md5_g(state1[19], state1[18], state1[17]) - state1[16] - md5_add[19];
		msg2[0] = rot_right(state2[20] - state2[19], 20) - md5_g(state2[19], state2[18], state2[17]) - state2[16] - md5_add[19];
		if(msg1[0] != msg2[0])
			continue;

		state1[1] = rot_left(md5_f(state1[0], state1[-1], state1[-2]) + state1[-3] + msg1[0] + md5_add[0], 7) + state1[0];
		state2[1] = state1[1];

		state1[2] = rot_left(md5_f(state1[1], state1[0], state1[-1]) + state1[-2] + msg1[1] + md5_add[1], 12) + state1[1];
		state2[2] = state1[2];
		msg1[2] = rot_right(state1[3] - state1[2], 17) - md5_f(state1[2], state1[1], state1[0]) - state1[-1] - md5_add[2];
		msg2[2] = msg1[2];

		msg1[3] = rot_right(state1[4] - state1[3], 22) - md5_f(state1[3], state1[2], state1[1]) - state1[0] - md5_add[3];
		msg2[3] = msg1[3];

		msg1[4] = rot_right(state1[5] - state1[4], 7) - md5_f(state1[4], state1[3], state1[2]) - state1[1] - md5_add[4];
		msg2[4] = rot_right(state2[5] - state2[4], 7) - md5_f(state2[4], state2[3], state2[2]) - state2[1] - md5_add[4];
		if((msg1[4] ^ msg2[4]) != 0x80000000)
			continue;

		msg1[5] = rot_right(state1[6] - state1[5], 12) - md5_f(state1[5], state1[4], state1[3]) - state1[2] - md5_add[5];
		msg2[5] = rot_right(state2[6] - state2[5], 12) - md5_f(state2[5], state2[4], state2[3]) - state2[2] - md5_add[5];
		if(msg1[5] != msg2[5])
			continue;

		/* A6 */
		state1[21] = rot_left(md5_g(state1[20], state1[19], state1[18]) + state1[17] + msg1[5] + md5_add[20], 5) + state1[20];
		state2[21] = rot_left(md5_g(state2[20], state2[19], state2[18]) + state2[17] + msg2[5] + md5_add[20], 5) + state2[20];
		if((state1[21] & 0x80020000) != (state1[20] & 0x00020000))
			continue;
		if((state1[21] ^ state2[21]) != 0x80000000)
			continue;

		/* D6 */
		state1[22] = rot_left(md5_g(state1[21], state1[20], state1[19]) + state1[18] + msg1[10] + md5_add[21], 9) + state1[21];
		state2[22] = rot_left(md5_g(state2[21], state2[20], state2[19]) + state2[18] + msg2[10] + md5_add[21], 9) + state2[21];
		if(state1[22] & 0x80000000)
			continue;
		if((state1[22] ^ state2[22]) != 0x80000000)
			continue;

		/* C6 */
		state1[23] = rot_left(md5_g(state1[22], state1[21], state1[20]) + state1[19] + msg1[15] + md5_add[22], 14) + state1[22];
		state2[23] = rot_left(md5_g(state2[22], state2[21], state2[20]) + state2[19] + msg2[15] + md5_add[22], 14) + state2[22];
		if(state1[23] & 0x80000000)
			continue;
		if(state1[23] != state2[23])
			continue;

		/* B6 */
		state1[24] = rot_left(md5_g(state1[23], state1[22], state1[21]) + state1[20] + msg1[4] + md5_add[23], 20) + state1[23];
		state2[24] = rot_left(md5_g(state2[23], state2[22], state2[21]) + state2[20] + msg2[4] + md5_add[23], 20) + state2[23];
		if(state1[24] != state2[24])
			continue;

		/* A7 */
		state1[25] = rot_left(md5_g(state1[24], state1[23], state1[22]) + state1[21] + msg1[9] + md5_add[24], 5) + state1[24];
		state2[25] = rot_left(md5_g(state2[24], state2[23], state2[22]) + state2[21] + msg2[9] + md5_add[24], 5) + state2[24];
		if(state1[25] != state2[25])
			continue;

		/* D7 */
		state1[26] = rot_left(md5_g(state1[25], state1[24], state1[23]) + state1[22] + msg1[14] + md5_add[25], 9) + state1[25];
		state2[26] = rot_left(md5_g(state2[25], state2[24], state2[23]) + state2[22] + msg2[14] + md5_add[25], 9) + state2[25];
		if(state1[26] != state2[26])
			continue;

		/* C7 */
		state1[27] = rot_left(md5_g(state1[26], state1[25], state1[24]) + state1[23] + msg1[3] + md5_add[26], 14) + state1[26];
		state2[27] = rot_left(md5_g(state2[26], state2[25], state2[24]) + state2[23] + msg2[3] + md5_add[26], 14) + state2[26];
		if(state1[27] != state2[27])
			continue;

		/* B7 */
		state1[28] = rot_left(md5_g(state1[27], state1[26], state1[25]) + state1[24] + msg1[8] + md5_add[27], 20) + state1[27];
		state2[28] = rot_left(md5_g(state2[27], state2[26], state2[25]) + state2[24] + msg2[8] + md5_add[27], 20) + state2[27];
		if(state1[28] != state2[28])
			continue;

		/* A8 */
		state1[29] = rot_left(md5_g(state1[28], state1[27], state1[26]) + state1[25] + msg1[13] + md5_add[28], 5) + state1[28];
		state2[29] = rot_left(md5_g(state2[28], state2[27], state2[26]) + state2[25] + msg2[13] + md5_add[28], 5) + state2[28];
		if(state1[29] != state2[29])
			continue;

		/* D8 */
		state1[30] = rot_left(md5_g(state1[29], state1[28], state1[27]) + state1[26] + msg1[2] + md5_add[29], 9) + state1[29];
		state2[30] = rot_left(md5_g(state2[29], state2[28], state2[27]) + state2[26] + msg2[2] + md5_add[29], 9) + state2[29];
		if(state1[30] != state2[30])
			continue;

		/* C8 */
		state1[31] = rot_left(md5_g(state1[30], state1[29], state1[28]) + state1[27] + msg1[7] + md5_add[30], 14) + state1[30];
		state2[31] = rot_left(md5_g(state2[30], state2[29], state2[28]) + state2[27] + msg2[7] + md5_add[30], 14) + state2[30];
		if(state1[31] != state2[31])
			continue;

		/* B8 */
		state1[32] = rot_left(md5_g(state1[31], state1[30], state1[29]) + state1[28] + msg1[12] + md5_add[31], 20) + state1[31];
		state2[32] = rot_left(md5_g(state2[31], state2[30], state2[29]) + state2[28] + msg2[12] + md5_add[31], 20) + state2[31];
		if(state1[32] != state2[32])
			continue;

		/* A9 */
		state1[33] = rot_left(md5_h(state1[32], state1[31], state1[30]) + state1[29] + msg1[5] + md5_add[32], 4) + state1[32];
		state2[33] = rot_left(md5_h(state2[32], state2[31], state2[30]) + state2[29] + msg2[5] + md5_add[32], 4) + state2[32];
		if(state1[33] != state2[33])
			continue;

		/* D9 */
		state1[34] = rot_left(md5_h(state1[33], state1[32], state1[31]) + state1[30] + msg1[8] + md5_add[33], 11) + state1[33];
		state2[34] = rot_left(md5_h(state2[33], state2[32], state2[31]) + state2[30] + msg2[8] + md5_add[33], 11) + state2[33];
		if(state1[34] != state2[34])
			continue;

		/* C9 */
		state1[35] = rot_left(md5_h(state1[34], state1[33], state1[32]) + state1[31] + msg1[11] + md5_add[34], 16) + state1[34];
		state2[35] = rot_left(md5_h(state2[34], state2[33], state2[32]) + state2[31] + msg2[11] + md5_add[34], 16) + state2[34];
		if((state1[35] ^ state2[35]) != 0x80000000)
			continue;

		/* B9 */
		state1[36] = rot_left(md5_h(state1[35], state1[34], state1[33]) + state1[32] + msg1[14] + md5_add[35], 23) + state1[35];
		state2[36] = rot_left(md5_h(state2[35], state2[34], state2[33]) + state2[32] + msg2[14] + md5_add[35], 23) + state2[35];
		if((state1[36] ^ state2[36]) != 0x80000000)
			continue;

		/* A10 */
		state1[37] = rot_left(md5_h(state1[36], state1[35], state1[34]) + state1[33] + msg1[1] + md5_add[36], 4) + state1[36];
		state2[37] = rot_left(md5_h(state2[36], state2[35], state2[34]) + state2[33] + msg2[1] + md5_add[36], 4) + state2[36];
		if((state1[37] ^ state2[37]) != 0x80000000)
			continue;

		/* D10 */
		state1[38] = rot_left(md5_h(state1[37], state1[36], state1[35]) + state1[34] + msg1[4] + md5_add[37], 11) + state1[37];
		state2[38] = rot_left(md5_h(state2[37], state2[36], state2[35]) + state2[34] + msg2[4] + md5_add[37], 11) + state2[37];
		if((state1[38] ^ state2[38]) != 0x80000000)
			continue;

		/* C10 */
		state1[39] = rot_left(md5_h(state1[38], state1[37], state1[36]) + state1[35] + msg1[7] + md5_add[38], 16) + state1[38];
		state2[39] = rot_left(md5_h(state2[38], state2[37], state2[36]) + state2[35] + msg2[7] + md5_add[38], 16) + state2[38];
		if((state1[39] ^ state2[39]) != 0x80000000)
			continue;

		/* B10 */
		state1[40] = rot_left(md5_h(state1[39], state1[38], state1[37]) + state1[36] + msg1[10] + md5_add[39], 23) + state1[39];
		state2[40] = rot_left(md5_h(state2[39], state2[38], state2[37]) + state2[36] + msg2[10] + md5_add[39], 23) + state2[39];
		if((state1[40] ^ state2[40]) != 0x80000000)
			continue;

		/* A11 */
		state1[41] = rot_left(md5_h(state1[40], state1[39], state1[38]) + state1[37] + msg1[13] + md5_add[40], 4) + state1[40];
		state2[41] = rot_left(md5_h(state2[40], state2[39], state2[38]) + state2[37] + msg2[13] + md5_add[40], 4) + state2[40];
		if((state1[41] ^ state2[41]) != 0x80000000)
			continue;

		/* D11 */
		state1[42] = rot_left(md5_h(state1[41], state1[40], state1[39]) + state1[38] + msg1[0] + md5_add[41], 11) + state1[41];
		state2[42] = rot_left(md5_h(state2[41], state2[40], state2[39]) + state2[38] + msg2[0] + md5_add[41], 11) + state2[41];
		if((state1[42] ^ state2[42]) != 0x80000000)
			continue;

		/* C11 */
		state1[43] = rot_left(md5_h(state1[42], state1[41], state1[40]) + state1[39] + msg1[3] + md5_add[42], 16) + state1[42];
		state2[43] = rot_left(md5_h(state2[42], state2[41], state2[40]) + state2[39] + msg2[3] + md5_add[42], 16) + state2[42];
		if((state1[43] ^ state2[43]) != 0x80000000)
			continue;

		/* B11 */
		state1[44] = rot_left(md5_h(state1[43], state1[42], state1[41]) + state1[40] + msg1[6] + md5_add[43], 23) + state1[43];
		state2[44] = rot_left(md5_h(state2[43], state2[42], state2[41]) + state2[40] + msg2[6] + md5_add[43], 23) + state2[43];
		if((state1[44] ^ state2[44]) != 0x80000000)
			continue;

		/* A12 */
		state1[45] = rot_left(md5_h(state1[44], state1[43], state1[42]) + state1[41] + msg1[9] + md5_add[44], 4) + state1[44];
		state2[45] = rot_left(md5_h(state2[44], state2[43], state2[42]) + state2[41] + msg2[9] + md5_add[44], 4) + state2[44];
		if((state1[45] ^ state2[45]) != 0x80000000)
			continue;

		/* D12 */
		state1[46] = rot_left(md5_h(state1[45], state1[44], state1[43]) + state1[42] + msg1[12] + md5_add[45], 11) + state1[45];
		state2[46] = rot_left(md5_h(state2[45], state2[44], state2[43]) + state2[42] + msg2[12] + md5_add[45], 11) + state2[45];
		if((state1[46] ^ state2[46]) != 0x80000000)
			continue;

		/* C12 */
		state1[47] = rot_left(md5_h(state1[46], state1[45], state1[44]) + state1[43] + msg1[15] + md5_add[46], 16) + state1[46];
		state2[47] = rot_left(md5_h(state2[46], state2[45], state2[44]) + state2[43] + msg2[15] + md5_add[46], 16) + state2[46];
		if((state1[47] ^ state2[47]) != 0x80000000)
			continue;

		/* B12 */
		state1[48] = rot_left(md5_h(state1[47], state1[46], state1[45]) + state1[44] + msg1[2] + md5_add[47], 23) + state1[47];
		state2[48] = rot_left(md5_h(state2[47], state2[46], state2[45]) + state2[44] + msg2[2] + md5_add[47], 23) + state2[47];
		if((state1[48] ^ state1[46]) & 0x80000000)
			continue;
		if((state1[48] ^ state2[48]) != 0x80000000)
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[0] + md5_add[48], 6) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[0] + md5_add[48], 6) + state2[48];
		if((state1[49] ^ state1[47]) & 0x80000000)
			continue;
		if((state1[49] ^ state2[49]) != 0x80000000)
			continue;

		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[7] + md5_add[49], 10) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[7] + md5_add[49], 10) + state2[49];
		if(!((state1[50] ^ state1[48]) & 0x80000000))
			continue;
		if((state1[50] ^ state2[50]) != 0x80000000)
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[14] + md5_add[50], 15) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[14] + md5_add[50], 15) + state2[50];
		if((state1[51] ^ state1[49]) & 0x80000000)
			continue;
		if((state1[51] ^ state2[51]) != 0x80000000)
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[5] + md5_add[51], 21) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[5] + md5_add[51], 21) + state2[51];
		if((state1[52] ^ state1[50]) & 0x80000000)
			continue;
		if((state1[52] ^ state2[52]) != 0x80000000)
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[12] + md5_add[52], 6) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[12] + md5_add[52], 6) + state2[52];
		if((state1[53] ^ state1[51]) & 0x80000000)
			continue;
		if((state1[53] ^ state2[53]) != 0x80000000)
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[3] + md5_add[53], 10) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[3] + md5_add[53], 10) + state2[53];
		if((state1[54] ^ state1[52]) & 0x80000000)
			continue;
		if((state1[54] ^ state2[54]) != 0x80000000)
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[10] + md5_add[54], 15) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[10] + md5_add[54], 15) + state2[54];
		if((state1[55] ^ state1[53]) & 0x80000000)
			continue;
		if((state1[55] ^ state2[55]) != 0x80000000)
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[1] + md5_add[55], 21) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[1] + md5_add[55], 21) + state2[55];
		if((state1[56] ^ state1[54]) & 0x80000000)
			continue;
		if((state1[56] ^ state2[56]) != 0x80000000)
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[8] + md5_add[56], 6) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[8] + md5_add[56], 6) + state2[56];
		if((state1[57] ^ state1[55]) & 0x80000000)
			continue;
		if((state1[57] ^ state2[57]) != 0x80000000)
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[15] + md5_add[57], 10) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[15] + md5_add[57], 10) + state2[57];
		if((state1[58] ^ state1[56]) & 0x80000000)
			continue;
		if((state1[58] ^ state2[58]) != 0x80000000)
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[6] + md5_add[58], 15) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[6] + md5_add[58], 15) + state2[58];
		if((state1[59] ^ state1[57]) & 0x80000000)
			continue;
		if((state1[59] ^ state2[59]) != 0x80000000)
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[13] + md5_add[59], 21) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[13] + md5_add[59], 21) + state2[59];
		if(state1[60] & 0x02000000)
			continue;
		if((state1[60] ^ state2[60]) != 0x80000000)
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[4] + md5_add[60], 6) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[4] + md5_add[60], 6) + state2[60];
		if((state1[61] ^ state2[61]) != 0x80000000)
			continue;

		/* D16 */
		state1[62] = rot_left(md5_i(state1[61], state1[60], state1[59]) + state1[58] + msg1[11] + md5_add[61], 10) + state1[61];
		state2[62] = rot_left(md5_i(state2[61], state2[60], state2[59]) + state2[58] + msg2[11] + md5_add[61], 10) + state2[61];
		if(state1[62] & 0x02000000)
			continue;
		if((state1[62] - state2[62]) != 0x7e000000)
			continue;

		/* C16 */
		state1[63] = rot_left(md5_i(state1[62], state1[61], state1[60]) + state1[59] + msg1[2] + md5_add[62], 15) + state1[62];
		state2[63] = rot_left(md5_i(state2[62], state2[61], state2[60]) + state2[59] + msg2[2] + md5_add[62], 15) + state2[62];
		if(((state1[63] + md5_iv[2]) & 0x86000000) != (((state1[62] + md5_iv[3]) & 0x80000000) | 0x02000000))
			continue;
		if((state1[63] - state2[63]) != 0x7e000000)
			continue;

		/* B16 */
		state1[64] = rot_left(md5_i(state1[63], state1[62], state1[61]) + state1[60] + msg1[9] + md5_add[63], 21) + state1[63];
		state2[64] = rot_left(md5_i(state2[63], state2[62], state2[61]) + state2[60] + msg2[9] + md5_add[63], 21) + state2[63];
		if(((state1[64] + md5_iv[1]) & 0x86000020) != ((state1[63] + md5_iv[2]) & 0x80000000))
			continue;
		if((state1[64] - state2[64]) != 0x7e000000)
			continue;

		return;
	}
}

void block2(
	uint32_t *msg1,
	uint32_t *msg2,
	uint32_t *state1,
	uint32_t *state2)
{
	size_t attempts = 0;

	for(;;)
	{
		++ attempts;
		if (attempts % 1000000 == 0)
			fprintf(stderr, "attempt (2) %d\n", attempts);

		/* A1 */
		state1[1] = (myrandom(17) | 0x84200000) & ~0x0a000820;
		state2[1] = state1[1] - 0x7e000000;

		msg1[16] = rot_right(state1[1] - state1[0], 7) - md5_f(state1[0], state1[-1], state1[-2]) - state1[-3] - md5_add[0];
		msg2[16] = rot_right(state2[1] - state2[0], 7) - md5_f(state2[0], state2[-1], state2[-2]) - state2[-3] - md5_add[0];
		if(msg1[16] != msg2[16])
			continue;

		/* D1 */
		state1[2] = (myrandom(18) | 0x8c000800) & ~(0x02208026 | 0x701f10c0);
		state1[2] |= (state1[1] & 0x701f10c0);
		state2[2] = state1[2] - 0x7dffffe0;

		msg1[17] = rot_right(state1[2] - state1[1], 12) - md5_f(state1[1], state1[0], state1[-1]) - state1[-2] - md5_add[1];
		msg2[17] = rot_right(state2[2] - state2[1], 12) - md5_f(state2[1], state2[0], state2[-1]) - state2[-2] - md5_add[1];
		if(msg1[17] != msg2[17])
			continue;

		/* C1 */
		state1[3] = (myrandom(19) | 0xbe1f0966) & ~(0x40201080 | 0x00000018);
		state1[3] |= (state1[2] & 0x00000018);
		state2[3] = state1[3] - 0x7dfef7e0;

		msg1[18] = rot_right(state1[3] - state1[2], 17) - md5_f(state1[2], state1[1], state1[0]) - state1[-1] - md5_add[2];
		msg2[18] = rot_right(state2[3] - state2[2], 17) - md5_f(state2[2], state2[1], state2[0]) - state2[-1] - md5_add[2];
		if(msg1[18] != msg2[18])
			continue;

		/* B1 */
		state1[4] = (myrandom(20) | 0xba040010) & ~(0x443b19ee | 0x00000601);
		state1[4] |= (state1[3] & 0x00000601);
		state2[4] = state1[4] - 0x7dffffe2;

		msg1[19] = rot_right(state1[4] - state1[3], 22) - md5_f(state1[3], state1[2], state1[1]) - state1[0] - md5_add[3];
		msg2[19] = rot_right(state2[4] - state2[3], 22) - md5_f(state2[3], state2[2], state2[1]) - state2[0] - md5_add[3];
		if(msg1[19] != msg2[19])
			continue;

		/* A2 */
		state1[5] = (myrandom(21) | 0x482f0e50) & ~0xb41011af;
		state2[5] = state1[5] - 0x7ffffcbf;

		msg1[20] = rot_right(state1[5] - state1[4], 7) - md5_f(state1[4], state1[3], state1[2]) - state1[1] - md5_add[4];
		msg2[20] = rot_right(state2[5] - state2[4], 7) - md5_f(state2[4], state2[3], state2[2]) - state2[1] - md5_add[4];
		if((msg1[20] ^ msg2[20]) != 0x80000000)
			continue;

		/* D2 */
		state1[6] = (myrandom(22) | 0x04220c56) & ~0x9a1113a9;
		state2[6] = state1[6] - 0x80110000;

		msg1[21] = rot_right(state1[6] - state1[5], 12) - md5_f(state1[5], state1[4], state1[3]) - state1[2] - md5_add[5];
		msg2[21] = rot_right(state2[6] - state2[5], 12) - md5_f(state2[5], state2[4], state2[3]) - state2[2] - md5_add[5];
		if(msg1[21] != msg2[21])
			continue;

		/* C2 */
		state1[7] = (myrandom(23) | 0x96011e01) & ~(0x083201c0 | 0x01808000);
		state1[7] |= (state1[6] & 0x01808000);
		state2[7] = state1[7] - 0x88000040;

		msg1[22] = rot_right(state1[7] - state1[6], 17) - md5_f(state1[6], state1[5], state1[4]) - state1[3] - md5_add[6];
		msg2[22] = rot_right(state2[7] - state2[6], 17) - md5_f(state2[6], state2[5], state2[4]) - state2[3] - md5_add[6];
		if(msg1[22] != msg2[22])
			continue;

		/* B2 */
		state1[8] = (myrandom(24) | 0x843283c0) & ~(0x1b810001 | 0x00000002);
		state1[8] |= (state1[7] & 0x00000002);
		state2[8] = state1[8] - 0x80818000;

		msg1[23] = rot_right(state1[8] - state1[7], 22) - md5_f(state1[7], state1[6], state1[5]) - state1[4] - md5_add[7];
		msg2[23] = rot_right(state2[8] - state2[7], 22) - md5_f(state2[7], state2[6], state2[5]) - state2[4] - md5_add[7];
		if(msg1[23] != msg2[23])
			continue;

		/* A3 */
		state1[9] = (myrandom(25) | 0x9c0101c1) & ~(0x03828202 | 0x00001000);
		state1[9] |= (state1[8] & 0x00001000);
		state2[9] = state1[9] - 0x7fffffbf;

		msg1[24] = rot_right(state1[9] - state1[8], 7) - md5_f(state1[8], state1[7], state1[6]) - state1[5] - md5_add[8];
		msg2[24] = rot_right(state2[9] - state2[8], 7) - md5_f(state2[8], state2[7], state2[6]) - state2[5] - md5_add[8];
		if(msg1[24] != msg2[24])
			continue;

		/* D3 */
		state1[10] = (myrandom(26) | 0x878383c0) & ~0x00041003;
		state2[10] = state1[10] - 0x7ffff000;

		msg1[25] = rot_right(state1[10] - state1[9], 12) - md5_f(state1[9], state1[8], state1[7]) - state1[6] - md5_add[9];
		msg2[25] = rot_right(state2[10] - state2[9], 12) - md5_f(state2[9], state2[8], state2[7]) - state2[6] - md5_add[9];
		if(msg1[25] != msg2[25])
			continue;

		/* C3 */
		state1[11] = (myrandom(27) | 0x800583c3) & ~(0x00021000 | 0x00086000);
		state1[11] |= (state1[10] & 0x00086000);
		state2[11] = state1[11] - 0x80000000;

		msg1[26] = rot_right(state1[11] - state1[10], 17) - md5_f(state1[10], state1[9], state1[8]) - state1[7] - md5_add[10];
		msg2[26] = rot_right(state2[11] - state2[10], 17) - md5_f(state2[10], state2[9], state2[8]) - state2[7] - md5_add[10];
		if(msg1[26] != msg2[26])
			continue;

		/* B3 */
		state1[12] = (myrandom(28) | 0x80081080) & ~(0x0007e000 | 0x7f000000);
		state1[12] |= (state1[11] & 0x7f000000);
		state2[12] = state1[12] - 0x80002080;

		msg1[27] = rot_right(state1[12] - state1[11], 22) - md5_f(state1[11], state1[10], state1[9]) - state1[8] - md5_add[11];
		msg2[27] = rot_right(state2[12] - state2[11], 22) - md5_f(state2[11], state2[10], state2[9]) - state2[8] - md5_add[11];
		if((msg1[27] ^ msg2[27]) != 0x00008000)
			continue;

		/* A4 */
		state1[13] = (myrandom(29) | 0x3f0fe008) & ~0x80000080;
		state2[13] = state1[13] - 0x7f000000;

		msg1[28] = rot_right(state1[13] - state1[12], 7) - md5_f(state1[12], state1[11], state1[10]) - state1[9] - md5_add[12];
		msg2[28] = rot_right(state2[13] - state2[12], 7) - md5_f(state2[12], state2[11], state2[10]) - state2[9] - md5_add[12];
		if(msg1[28] != msg2[28])
			continue;

		/* D4 */
		state1[14] = (myrandom(30) | 0x400be088) & ~0xbf040000;
		state2[14] = state1[14] - 0x80000000;

		msg1[29] = rot_right(state1[14] - state1[13], 12) - md5_f(state1[13], state1[12], state1[11]) - state1[10] - md5_add[13];
		msg2[29] = rot_right(state2[14] - state2[13], 12) - md5_f(state2[13], state2[12], state2[11]) - state2[10] - md5_add[13];
		if(msg1[29] != msg2[29])
			continue;

		/* C4 */
		state1[15] = (myrandom(31) | 0x7d000000) & ~0x82008008;
		state2[15] = state1[15] - 0x7fff7ff8;

		msg1[30] = rot_right(state1[15] - state1[14], 17) - md5_f(state1[14], state1[13], state1[12]) - state1[11] - md5_add[14];
		msg2[30] = rot_right(state2[15] - state2[14], 17) - md5_f(state2[14], state2[13], state2[12]) - state2[11] - md5_add[14];
		if((msg1[30] ^ msg2[30]) != 0x80000000)
			continue;

		/* B4 */
		state1[16] = myrandom(33);
		state2[16] = state1[16] - 0xa0000000;

		msg1[31] = rot_right(state1[16] - state1[15], 22) - md5_f(state1[15], state1[14], state1[13]) - state1[12] - md5_add[15];
		msg2[31] = rot_right(state2[16] - state2[15], 22) - md5_f(state2[15], state2[14], state2[13]) - state2[12] - md5_add[15];
		if(msg1[31] != msg2[31])
			continue;

		/* A5 */
		state1[17] = rot_left(md5_g(state1[16], state1[15], state1[14]) + state1[13] + msg1[17] + md5_add[16], 5) + state1[16];
		state2[17] = rot_left(md5_g(state2[16], state2[15], state2[14]) + state2[13] + msg2[17] + md5_add[16], 5) + state2[16];
		if((state1[17] & 0x80028008) != (state1[16] & 0x00008008))
			continue;
		if((state1[17] ^ state2[17]) != 0x80000000)
			continue;

		/* D5 */
		state1[18] = rot_left(md5_g(state1[17], state1[16], state1[15]) + state1[14] + msg1[22] + md5_add[17], 9) + state1[17];
		state2[18] = rot_left(md5_g(state2[17], state2[16], state2[15]) + state2[14] + msg2[22] + md5_add[17], 9) + state2[17];
		if((state1[18] & 0xa0020000) != ((state1[17] & 0x20000000) | 0x00020000))
			continue;
		if((state1[18] ^ state2[18]) != 0x80000000)
			continue;

		/* C5 */
		state1[19] = rot_left(md5_g(state1[18], state1[17], state1[16]) + state1[15] + msg1[27] + md5_add[18], 14) + state1[18];
		state2[19] = rot_left(md5_g(state2[18], state2[17], state2[16]) + state2[15] + msg2[27] + md5_add[18], 14) + state2[18];
		if(state1[19] & 0x80020000)
			continue;
		if((state1[19] - state2[19]) != 0x7ffe0000)
			continue;

		/* B5 */
		state1[20] = rot_left(md5_g(state1[19], state1[18], state1[17]) + state1[16] + msg1[16] + md5_add[19], 20) + state1[19];
		state2[20] = rot_left(md5_g(state2[19], state2[18], state2[17]) + state2[16] + msg2[16] + md5_add[19], 20) + state2[19];
		if(state1[20] & 0x80000000)
			continue;
		if((state1[20] ^ state2[20]) != 0x80000000)
			continue;

		/* A6 */
		state1[21] = rot_left(md5_g(state1[20], state1[19], state1[18]) + state1[17] + msg1[21] + md5_add[20], 5) + state1[20];
		state2[21] = rot_left(md5_g(state2[20], state2[19], state2[18]) + state2[17] + msg2[21] + md5_add[20], 5) + state2[20];
		if((state1[21] & 0x80020000) != (state1[20] & 0x00020000))
			continue;
		if((state1[21] ^ state2[21]) != 0x80000000)
			continue;

		/* D6 */
		state1[22] = rot_left(md5_g(state1[21], state1[20], state1[19]) + state1[18] + msg1[26] + md5_add[21], 9) + state1[21];
		state2[22] = rot_left(md5_g(state2[21], state2[20], state2[19]) + state2[18] + msg2[26] + md5_add[21], 9) + state2[21];
		if(state1[22] & 0x80000000)
			continue;
		if((state1[22] ^ state2[22]) != 0x80000000)
			continue;

		/* C6 */
		state1[23] = rot_left(md5_g(state1[22], state1[21], state1[20]) + state1[19] + msg1[31] + md5_add[22], 14) + state1[22];
		state2[23] = rot_left(md5_g(state2[22], state2[21], state2[20]) + state2[19] + msg2[31] + md5_add[22], 14) + state2[22];
		if(state1[23] & 0x80000000)
			continue;
		if(state1[23] != state2[23])
			continue;

		/* B6 */
		state1[24] = rot_left(md5_g(state1[23], state1[22], state1[21]) + state1[20] + msg1[20] + md5_add[23], 20) + state1[23];
		state2[24] = rot_left(md5_g(state2[23], state2[22], state2[21]) + state2[20] + msg2[20] + md5_add[23], 20) + state2[23];
		if(state1[24] != state2[24])
			continue;

		/* A7 */
		state1[25] = rot_left(md5_g(state1[24], state1[23], state1[22]) + state1[21] + msg1[25] + md5_add[24], 5) + state1[24];
		state2[25] = rot_left(md5_g(state2[24], state2[23], state2[22]) + state2[21] + msg2[25] + md5_add[24], 5) + state2[24];
		if(state1[25] != state2[25])
			continue;

		/* D7 */
		state1[26] = rot_left(md5_g(state1[25], state1[24], state1[23]) + state1[22] + msg1[30] + md5_add[25], 9) + state1[25];
		state2[26] = rot_left(md5_g(state2[25], state2[24], state2[23]) + state2[22] + msg2[30] + md5_add[25], 9) + state2[25];
		if(state1[26] != state2[26])
			continue;

		/* C7 */
		state1[27] = rot_left(md5_g(state1[26], state1[25], state1[24]) + state1[23] + msg1[19] + md5_add[26], 14) + state1[26];
		state2[27] = rot_left(md5_g(state2[26], state2[25], state2[24]) + state2[23] + msg2[19] + md5_add[26], 14) + state2[26];
		if(state1[27] != state2[27])
			continue;

		/* B7 */
		state1[28] = rot_left(md5_g(state1[27], state1[26], state1[25]) + state1[24] + msg1[24] + md5_add[27], 20) + state1[27];
		state2[28] = rot_left(md5_g(state2[27], state2[26], state2[25]) + state2[24] + msg2[24] + md5_add[27], 20) + state2[27];
		if(state1[28] != state2[28])
			continue;

		/* A8 */
		state1[29] = rot_left(md5_g(state1[28], state1[27], state1[26]) + state1[25] + msg1[29] + md5_add[28], 5) + state1[28];
		state2[29] = rot_left(md5_g(state2[28], state2[27], state2[26]) + state2[25] + msg2[29] + md5_add[28], 5) + state2[28];
		if(state1[29] != state2[29])
			continue;

		/* D8 */
		state1[30] = rot_left(md5_g(state1[29], state1[28], state1[27]) + state1[26] + msg1[18] + md5_add[29], 9) + state1[29];
		state2[30] = rot_left(md5_g(state2[29], state2[28], state2[27]) + state2[26] + msg2[18] + md5_add[29], 9) + state2[29];
		if(state1[30] != state2[30])
			continue;

		/* C8 */
		state1[31] = rot_left(md5_g(state1[30], state1[29], state1[28]) + state1[27] + msg1[23] + md5_add[30], 14) + state1[30];
		state2[31] = rot_left(md5_g(state2[30], state2[29], state2[28]) + state2[27] + msg2[23] + md5_add[30], 14) + state2[30];
		if(state1[31] != state2[31])
			continue;

		/* B8 */
		state1[32] = rot_left(md5_g(state1[31], state1[30], state1[29]) + state1[28] + msg1[28] + md5_add[31], 20) + state1[31];
		state2[32] = rot_left(md5_g(state2[31], state2[30], state2[29]) + state2[28] + msg2[28] + md5_add[31], 20) + state2[31];
		if(state1[32] != state2[32])
			continue;

		/* A9 */
		state1[33] = rot_left(md5_h(state1[32], state1[31], state1[30]) + state1[29] + msg1[21] + md5_add[32], 4) + state1[32];
		state2[33] = rot_left(md5_h(state2[32], state2[31], state2[30]) + state2[29] + msg2[21] + md5_add[32], 4) + state2[32];
		if(state1[33] != state2[33])
			continue;

		/* D9 */
		state1[34] = rot_left(md5_h(state1[33], state1[32], state1[31]) + state1[30] + msg1[24] + md5_add[33], 11) + state1[33];
		state2[34] = rot_left(md5_h(state2[33], state2[32], state2[31]) + state2[30] + msg2[24] + md5_add[33], 11) + state2[33];
		if(state1[34] != state2[34])
			continue;

		/* C9 */
		state1[35] = rot_left(md5_h(state1[34], state1[33], state1[32]) + state1[31] + msg1[27] + md5_add[34], 16) + state1[34];
		state2[35] = rot_left(md5_h(state2[34], state2[33], state2[32]) + state2[31] + msg2[27] + md5_add[34], 16) + state2[34];
		if((state1[35] ^ state2[35]) != 0x80000000)
			continue;

		/* B9 */
		state1[36] = rot_left(md5_h(state1[35], state1[34], state1[33]) + state1[32] + msg1[30] + md5_add[35], 23) + state1[35];
		state2[36] = rot_left(md5_h(state2[35], state2[34], state2[33]) + state2[32] + msg2[30] + md5_add[35], 23) + state2[35];
		if((state1[36] ^ state2[36]) != 0x80000000)
			continue;

		/* A10 */
		state1[37] = rot_left(md5_h(state1[36], state1[35], state1[34]) + state1[33] + msg1[17] + md5_add[36], 4) + state1[36];
		state2[37] = rot_left(md5_h(state2[36], state2[35], state2[34]) + state2[33] + msg2[17] + md5_add[36], 4) + state2[36];
		if((state1[37] ^ state2[37]) != 0x80000000)
			continue;

		/* D10 */
		state1[38] = rot_left(md5_h(state1[37], state1[36], state1[35]) + state1[34] + msg1[20] + md5_add[37], 11) + state1[37];
		state2[38] = rot_left(md5_h(state2[37], state2[36], state2[35]) + state2[34] + msg2[20] + md5_add[37], 11) + state2[37];
		if((state1[38] ^ state2[38]) != 0x80000000)
			continue;

		/* C10 */
		state1[39] = rot_left(md5_h(state1[38], state1[37], state1[36]) + state1[35] + msg1[23] + md5_add[38], 16) + state1[38];
		state2[39] = rot_left(md5_h(state2[38], state2[37], state2[36]) + state2[35] + msg2[23] + md5_add[38], 16) + state2[38];
		if((state1[39] ^ state2[39]) != 0x80000000)
			continue;

		/* B10 */
		state1[40] = rot_left(md5_h(state1[39], state1[38], state1[37]) + state1[36] + msg1[26] + md5_add[39], 23) + state1[39];
		state2[40] = rot_left(md5_h(state2[39], state2[38], state2[37]) + state2[36] + msg2[26] + md5_add[39], 23) + state2[39];
		if((state1[40] ^ state2[40]) != 0x80000000)
			continue;

		/* A11 */
		state1[41] = rot_left(md5_h(state1[40], state1[39], state1[38]) + state1[37] + msg1[29] + md5_add[40], 4) + state1[40];
		state2[41] = rot_left(md5_h(state2[40], state2[39], state2[38]) + state2[37] + msg2[29] + md5_add[40], 4) + state2[40];
		if((state1[41] ^ state2[41]) != 0x80000000)
			continue;

		/* D11 */
		state1[42] = rot_left(md5_h(state1[41], state1[40], state1[39]) + state1[38] + msg1[16] + md5_add[41], 11) + state1[41];
		state2[42] = rot_left(md5_h(state2[41], state2[40], state2[39]) + state2[38] + msg2[16] + md5_add[41], 11) + state2[41];
		if((state1[42] ^ state2[42]) != 0x80000000)
			continue;

		/* C11 */
		state1[43] = rot_left(md5_h(state1[42], state1[41], state1[40]) + state1[39] + msg1[19] + md5_add[42], 16) + state1[42];
		state2[43] = rot_left(md5_h(state2[42], state2[41], state2[40]) + state2[39] + msg2[19] + md5_add[42], 16) + state2[42];
		if((state1[43] ^ state2[43]) != 0x80000000)
			continue;

		/* B11 */
		state1[44] = rot_left(md5_h(state1[43], state1[42], state1[41]) + state1[40] + msg1[22] + md5_add[43], 23) + state1[43];
		state2[44] = rot_left(md5_h(state2[43], state2[42], state2[41]) + state2[40] + msg2[22] + md5_add[43], 23) + state2[43];
		if((state1[44] ^ state2[44]) != 0x80000000)
			continue;

		/* A12 */
		state1[45] = rot_left(md5_h(state1[44], state1[43], state1[42]) + state1[41] + msg1[25] + md5_add[44], 4) + state1[44];
		state2[45] = rot_left(md5_h(state2[44], state2[43], state2[42]) + state2[41] + msg2[25] + md5_add[44], 4) + state2[44];
		if((state1[45] ^ state2[45]) != 0x80000000)
			continue;

		/* D12 */
		state1[46] = rot_left(md5_h(state1[45], state1[44], state1[43]) + state1[42] + msg1[28] + md5_add[45], 11) + state1[45];
		state2[46] = rot_left(md5_h(state2[45], state2[44], state2[43]) + state2[42] + msg2[28] + md5_add[45], 11) + state2[45];
		if((state1[46] ^ state2[46]) != 0x80000000)
			continue;

		/* C12 */
		state1[47] = rot_left(md5_h(state1[46], state1[45], state1[44]) + state1[43] + msg1[31] + md5_add[46], 16) + state1[46];
		state2[47] = rot_left(md5_h(state2[46], state2[45], state2[44]) + state2[43] + msg2[31] + md5_add[46], 16) + state2[46];
		if((state1[47] ^ state2[47]) != 0x80000000)
			continue;

		/* B12 */
		state1[48] = rot_left(md5_h(state1[47], state1[46], state1[45]) + state1[44] + msg1[18] + md5_add[47], 23) + state1[47];
		state2[48] = rot_left(md5_h(state2[47], state2[46], state2[45]) + state2[44] + msg2[18] + md5_add[47], 23) + state2[47];
		if((state1[48] & 0x80000000) != (state1[46] & 0x80000000))
			continue;
		if((state1[48] ^ state2[48]) != 0x80000000)
			continue;

		/* A13 */
		state1[49] = rot_left(md5_i(state1[48], state1[47], state1[46]) + state1[45] + msg1[16] + md5_add[48], 6) + state1[48];
		state2[49] = rot_left(md5_i(state2[48], state2[47], state2[46]) + state2[45] + msg2[16] + md5_add[48], 6) + state2[48];
		if((state1[49] & 0x80000000) != (state1[47] & 0x80000000))
			continue;
		if((state1[49] ^ state2[49]) != 0x80000000)
			continue;

		/* D13 */
		state1[50] = rot_left(md5_i(state1[49], state1[48], state1[47]) + state1[46] + msg1[23] + md5_add[49], 10) + state1[49];
		state2[50] = rot_left(md5_i(state2[49], state2[48], state2[47]) + state2[46] + msg2[23] + md5_add[49], 10) + state2[49];
		if((state1[50] ^ state2[50]) != 0x80000000)
			continue;

		/* C13 */
		state1[51] = rot_left(md5_i(state1[50], state1[49], state1[48]) + state1[47] + msg1[30] + md5_add[50], 15) + state1[50];
		state2[51] = rot_left(md5_i(state2[50], state2[49], state2[48]) + state2[47] + msg2[30] + md5_add[50], 15) + state2[50];
		if((state1[51] & 0x80000000) != (state1[49] & 0x80000000))
			continue;
		if((state1[51] ^ state2[51]) != 0x80000000)
			continue;

		/* B13 */
		state1[52] = rot_left(md5_i(state1[51], state1[50], state1[49]) + state1[48] + msg1[21] + md5_add[51], 21) + state1[51];
		state2[52] = rot_left(md5_i(state2[51], state2[50], state2[49]) + state2[48] + msg2[21] + md5_add[51], 21) + state2[51];
		if((state1[52] & 0x80000000) != (state1[50] & 0x80000000))
			continue;
		if((state1[52] ^ state2[52]) != 0x80000000)
			continue;

		/* A14 */
		state1[53] = rot_left(md5_i(state1[52], state1[51], state1[50]) + state1[49] + msg1[28] + md5_add[52], 6) + state1[52];
		state2[53] = rot_left(md5_i(state2[52], state2[51], state2[50]) + state2[49] + msg2[28] + md5_add[52], 6) + state2[52];
		if((state1[53] & 0x80000000) != (state1[51] & 0x80000000))
			continue;
		if((state1[53] ^ state2[53]) != 0x80000000)
			continue;

		/* D14 */
		state1[54] = rot_left(md5_i(state1[53], state1[52], state1[51]) + state1[50] + msg1[19] + md5_add[53], 10) + state1[53];
		state2[54] = rot_left(md5_i(state2[53], state2[52], state2[51]) + state2[50] + msg2[19] + md5_add[53], 10) + state2[53];
		if((state1[54] & 0x80000000) != (state1[52] & 0x80000000))
			continue;
		if((state1[54] ^ state2[54]) != 0x80000000)
			continue;

		/* C14 */
		state1[55] = rot_left(md5_i(state1[54], state1[53], state1[52]) + state1[51] + msg1[26] + md5_add[54], 15) + state1[54];
		state2[55] = rot_left(md5_i(state2[54], state2[53], state2[52]) + state2[51] + msg2[26] + md5_add[54], 15) + state2[54];
		if((state1[55] & 0x80000000) != (state1[53] & 0x80000000))
			continue;
		if((state1[55] ^ state2[55]) != 0x80000000)
			continue;

		/* B14 */
		state1[56] = rot_left(md5_i(state1[55], state1[54], state1[53]) + state1[52] + msg1[17] + md5_add[55], 21) + state1[55];
		state2[56] = rot_left(md5_i(state2[55], state2[54], state2[53]) + state2[52] + msg2[17] + md5_add[55], 21) + state2[55];
		if((state1[56] & 0x80000000) != (state1[54] & 0x80000000))
			continue;
		if((state1[56] ^ state2[56]) != 0x80000000)
			continue;

		/* A15 */
		state1[57] = rot_left(md5_i(state1[56], state1[55], state1[54]) + state1[53] + msg1[24] + md5_add[56], 6) + state1[56];
		state2[57] = rot_left(md5_i(state2[56], state2[55], state2[54]) + state2[53] + msg2[24] + md5_add[56], 6) + state2[56];
		if((state1[57] & 0x80000000) != (state1[55] & 0x80000000))
			continue;
		if((state1[57] ^ state2[57]) != 0x80000000)
			continue;

		/* D15 */
		state1[58] = rot_left(md5_i(state1[57], state1[56], state1[55]) + state1[54] + msg1[31] + md5_add[57], 10) + state1[57];
		state2[58] = rot_left(md5_i(state2[57], state2[56], state2[55]) + state2[54] + msg2[31] + md5_add[57], 10) + state2[57];
		if((state1[58] & 0x80000000) != (state1[56] & 0x80000000))
			continue;
		if((state1[58] ^ state2[58]) != 0x80000000)
			continue;

		/* C15 */
		state1[59] = rot_left(md5_i(state1[58], state1[57], state1[56]) + state1[55] + msg1[22] + md5_add[58], 15) + state1[58];
		state2[59] = rot_left(md5_i(state2[58], state2[57], state2[56]) + state2[55] + msg2[22] + md5_add[58], 15) + state2[58];
		if((state1[59] & 0x80000000) != (state1[57] & 0x80000000))
			continue;
		if((state1[59] ^ state2[59]) != 0x80000000)
			continue;

		/* B15 */
		state1[60] = rot_left(md5_i(state1[59], state1[58], state1[57]) + state1[56] + msg1[29] + md5_add[59], 21) + state1[59];
		state2[60] = rot_left(md5_i(state2[59], state2[58], state2[57]) + state2[56] + msg2[29] + md5_add[59], 21) + state2[59];
		if((state1[60] ^ state2[60]) != 0x80000000)
			continue;

		/* A16 */
		state1[61] = rot_left(md5_i(state1[60], state1[59], state1[58]) + state1[57] + msg1[20] + md5_add[60], 6) + state1[60];
		state2[61] = rot_left(md5_i(state2[60], state2[59], state2[58]) + state2[57] + msg2[20] + md5_add[60], 6) + state2[60];
		if((state1[61] ^ state2[61]) != 0x80000000)
			continue;
		if((state1[-3] + state1[61]) != (state2[-3] + state2[61]))
			continue;

		/* D16 */
		state1[62] = rot_left(md5_i(state1[61], state1[60], state1[59]) + state1[58] + msg1[27] + md5_add[61], 10) + state1[61];
		state2[62] = rot_left(md5_i(state2[61], state2[60], state2[59]) + state2[58] + msg2[27] + md5_add[61], 10) + state2[61];
		if((state1[-2] + state1[62]) != (state2[-2] + state2[62]))
			continue;

		/* C16 */
		state1[63] = rot_left(md5_i(state1[62], state1[61], state1[60]) + state1[59] + msg1[18] + md5_add[62], 15) + state1[62];
		state2[63] = rot_left(md5_i(state2[62], state2[61], state2[60]) + state2[59] + msg2[18] + md5_add[62], 15) + state2[62];
		if((state1[-1] + state1[63]) != (state2[-1] + state2[63]))
			continue;

		/* B16 */
		state1[64] = rot_left(md5_i(state1[63], state1[62], state1[61]) + state1[60] + msg1[25] + md5_add[63], 21) + state1[63];
		state2[64] = rot_left(md5_i(state2[63], state2[62], state2[61]) + state2[60] + msg2[25] + md5_add[63], 21) + state2[63];
		if((state1[0] + state1[64]) != (state2[0] + state2[64]))
			continue;

		return;
	}
}

void gen_collisions(uint32_t msg1[32], uint32_t msg2[32])
{
	uint32_t state1real[65+4], state2real[65+4];
	uint32_t *state1, *state2;

	state1 = state1real+4;
	state2 = state2real+4;
	state1[-3] = state2[-3] = md5_iv[0];
	state1[-2] = state2[-2] = md5_iv[3];
	state1[-1] = state2[-1] = md5_iv[2];
	state1[0] = state2[0] = md5_iv[1];

	block1(msg1, msg2, state1, state2);

	state1[-3] += state1[61];
	state1[-2] += state1[62];
	state1[-1] += state1[63];
	state1[0] += state1[64];

	state2[-3] += state2[61];
	state2[-2] += state2[62];
	state2[-1] += state2[63];
	state2[0] += state2[64];

	block2(msg1, msg2, state1, state2);
}

int main(int argc, char *argv[])
{
	size_t i;
	uint32_t msg1[32], msg2[32];

	randoms[0] = 0x272041c9;
	randoms[1] = 0x36d69572;
	randoms[2] = 0x0967f364;
	randoms[3] = 0x471aad20;
	randoms[4] = 0x58b34b54;
	randoms[5] = 0x2cad4fe2;
	randoms[6] = 0x57085139;
	randoms[7] = 0x3d1504ff;
	randoms[8] = 0x6367e309;
	randoms[9] = 0x4776fe20;
	randoms[10] = 0x648c154d;
	randoms[11] = 0x5c65c980;
	randoms[12] = 0x556e2d59;
	randoms[13] = 0x0e3bf852;
	randoms[14] = 0x45c4ad14;
	randoms[15] = 0x52e532e8;
	randoms[16] = 0x3560958c;
	randoms[17] = 0x3b73fe0a;
	randoms[18] = 0x61a9629c;
	randoms[19] = 0x625cb56d;
	randoms[20] = 0x5a7b7873;
	randoms[21] = 0x6f5212c1;
	randoms[22] = 0x1221ccd4;
	randoms[23] = 0x0f8a220f;
	randoms[24] = 0x22ad66e4;
	randoms[25] = 0x10093f5e;
	randoms[26] = 0x62fe2069;
	randoms[27] = 0x71b49060;
	randoms[28] = 0x4aa7106c;
	randoms[29] = 0x27394180;
	randoms[30] = 0x6d50766b;
	randoms[31] = 0x31d459ed;
	randoms[32] = 0x0d585cde;
	randoms[33] = 0x624e6371;
	randoms[34] = 0x00000000;
	randoms[35] = 0x00000000;
	randoms[36] = 0x00000000;
	randoms[37] = 0x00000000;
	randoms[38] = 0x00000000;
	randoms[39] = 0x00000000;

	srandom(time(NULL));
	gen_collisions(msg1, msg2);

	for (i = 0; i < 32; i ++)
		printf("%08x", to_big_endian(msg1[i]));
	puts("");

	for (i = 0; i < 32; i ++)
		printf("%08x", to_big_endian(msg2[i]));
	puts("");

	return 0;
}
