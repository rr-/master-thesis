#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include "sc.h"
#include "tick.h"
#include "md4.h"
#include "md4rev.h"
#include "md4coll_block1.h"

void gen_collisions(uint32_t msg1[16], uint32_t msg2[16])
{
	uint32_t state1real[52], state2real[52];
	uint32_t *state1, *state2;

	/*
		simple hack to conveniently make array indexing easier:
		arr[-1] <=> (arr+(-1))
	*/
	state1 = state1real + 4;
	state2 = state2real + 4;
	state1[-4] = state2[-4] = md4_iv[0]; /* a0 */
	state1[-3] = state2[-3] = md4_iv[3]; /* d0 */
	state1[-2] = state2[-2] = md4_iv[2]; /* c0 */
	state1[-1] = state2[-1] = md4_iv[1]; /* b0 */

	block1(msg1, msg2, state1, state2, message_delta);
	dump_state(msg1, msg2, 16, state1, state2, 48);
}

int main(void)
{
	size_t i;
	uint32_t msg1[16], msg2[16];

	srandom(time(NULL));
	gen_collisions(msg1, msg2);

	for (i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg1[i]));
	puts("");

	for (i = 0; i < 16; i++)
		printf("%08x", to_big_endian(msg2[i]));
	puts("");

	return 0;
}
