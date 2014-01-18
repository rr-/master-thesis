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

uint32_t bit_at(uint32_t x, size_t index)
{
	return (x >> index) & 1;
}

uint32_t set_bit(uint32_t x, bool bit, size_t position)
{
	if (bit)
		x |= (1 << position);
	else
		x &= ~(1 << position);
	return x;
}
