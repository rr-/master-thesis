#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

int is_big_endian(void);
uint32_t rot_left(uint32_t x, size_t bits);
uint32_t rot_right(uint32_t x, size_t bits);
uint32_t swap_endian(uint32_t x);
uint32_t to_little_endian(uint32_t x);
uint32_t to_big_endian(uint32_t x);
uint32_t from_little_endian(uint32_t x);
uint32_t from_big_endian(uint32_t x);
bool bit_at(uint32_t x, size_t index);
uint32_t set_bit(uint32_t x, bool bit, size_t position);
void comb(int m, int n, void (*report)(int n, unsigned int *c));
#endif
