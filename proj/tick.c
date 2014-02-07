#include "tick.h"
#include <stdio.h>

void tick_init(tick_context *const tc, unsigned long repeat)
{
	tc->done = 0L;
	tc->counter = 0L;
	tc->repeat = repeat;
}

void tick(tick_context *const tc, const char *const msg)
{
	++ tc->counter;
	if (tc->counter == tc->repeat)
	{
		++ tc->done;

		if (msg != NULL)
			fprintf(stderr, "%s: ", msg);
		fprintf(stderr, "attempt %llu", tc->done * tc->counter);
		fprintf(stderr, "\n");

		tc->counter = 0L;
	}
}
