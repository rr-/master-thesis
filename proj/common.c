#include "common.h"

int is_big_endian(void)
{
	union {
		uint32_t i;
		char c[4];
	} bint = {0x01020304};
	return bint.c[0] == 1;
}

uint32_t rot_left(uint32_t x, size_t bits)
{
	return (x << bits) | ((x & 0xffffffff) >> (32 - bits));
}

uint32_t rot_right(uint32_t x, size_t bits)
{
	return (x >> bits) | ((x & 0xffffffff) << (32 - bits));
}

uint32_t swap_endian(uint32_t x)
{
	return
		((x >> 24) & 0xff) |
		((x >> 8) & 0xff00) |
		((x << 8) & 0xff0000) |
		((x << 24) & 0xff000000);
}

uint32_t to_little_endian(uint32_t x)
{
	return is_big_endian() ? swap_endian(x) : x;
}

uint32_t to_big_endian(uint32_t x)
{
	return is_big_endian() ? x : swap_endian(x);
}

uint32_t from_little_endian(uint32_t x)
{
	return is_big_endian() ? swap_endian(x) : x;
}

uint32_t from_big_endian(uint32_t x)
{
	return is_big_endian() ? x : swap_endian(x);
}

bool bit_at(uint32_t x, size_t index)
{
	return ((x >> index) & 1) == 1;
}

uint32_t set_bit(uint32_t x, bool bit, size_t position)
{
	if (bit)
		x |= (1 << position);
	else
		x &= ~(1 << position);
	return x;
}

void comb_helper(int m, int n, int pos, unsigned int *buf, void (*report)(int n, unsigned int *c))
{
	int i;
	if (pos >= n)
	{
		report(n, buf);
		return;
	}
	for (i = 0; i < m; i ++)
	{
		buf[pos] = i + 1;
		comb_helper(m, n, pos + 1, buf, report);
	}
}

void comb(int m, int n, void (*report)(int n, unsigned int *c))
{
	unsigned int *buf = (unsigned int*) malloc(n * sizeof(unsigned int));
	comb_helper(m, n, 0, buf, report);
}

size_t hamming(uint32_t a, uint32_t b)
{
	size_t i, result = 0;
	uint32_t xor = a ^ b;
	for (i = 0; i < 8*sizeof(uint32_t); i ++)
	{
		if (xor & (1 << i))
			result ++;
	}
	return result;
}
