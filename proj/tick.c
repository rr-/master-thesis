#include "tick.h"
#include <stdio.h>

void tick_init(tick_context *const tc)
{
	tc->done = 0L;
	tc->counter = 0L;
}

void tick(tick_context *const tc, const char *const msg)
{
	++ tc->counter;
	if (tc->counter == 1000000L)
	{
		++ tc->done;

		fprintf(stderr, "attempt %llu", tc->done * tc->counter);
		if (msg != NULL)
			fprintf(stderr, " (%s)", msg);
		fprintf(stderr, "\n");

		tc->counter = 0L;
	}
}
