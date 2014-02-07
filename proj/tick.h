#ifndef TICK_H
#define TICK_H

typedef struct
{
	unsigned long long done;
	unsigned long long counter;
	unsigned long repeat;
} tick_context;

void tick_init(tick_context *const tc, unsigned long repeat);
void tick(tick_context *const tc, const char *const msg);

#endif
