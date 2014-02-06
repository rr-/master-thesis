#ifndef TICK_H
#define TICK_H

typedef struct
{
	unsigned long long done;
	unsigned long long counter;
} tick_context;

void tick_init(tick_context *const tc);
void tick(tick_context *const tc, const char *const msg);

#endif
