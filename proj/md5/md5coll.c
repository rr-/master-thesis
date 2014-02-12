#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "common.h"
#include "sc.h"
#include "tick.h"
#include "md5.h"
#include "md5rev.h"
#include "md5coll_block1.h"
#include "md5coll_block2.h"

void gen_collisions(uint32_t msg1[32], uint32_t msg2[32])
{
	uint32_t state1real[68], state2real[68];
	uint32_t *state1, *state2;
	size_t i;

	state1 = state1real + 4;
	state2 = state2real + 4;
	state1[-4] = state2[-4] = md5_iv[0];
	state1[-3] = state2[-3] = md5_iv[3];
	state1[-2] = state2[-2] = md5_iv[2];
	state1[-1] = state2[-1] = md5_iv[1];

	block1(msg1, msg2, state1, state2, message_delta);
	dump_state(msg1, msg2, 32, state1, state2, 64);

	for (i = 60; i < 64; i ++)
	{
		state1[i - 64] += state1[i];
		state2[i - 64] += state2[i];
	}

	block2(msg1, msg2, state1, state2, message_delta);
	dump_state(msg1, msg2, 32, state1, state2, 64);
}

int main(int argc, char *argv[])
{
	size_t i;
	uint32_t msg1[32], msg2[32];

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
