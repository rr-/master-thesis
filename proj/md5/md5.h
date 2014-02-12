#ifndef MD5_H
#define MD5_H
#include <stdint.h>
#include <stddef.h>

uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z);
uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z);
uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z);
uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z);

extern const uint32_t md5_iv[4];
extern const uint32_t md5_shift[64];
extern const uint32_t md5_msg_index[64];
extern const uint32_t md5_add[64];

extern uint32_t (*const md5_round_func[64])(
	uint32_t x,
	uint32_t y,
	uint32_t z);

void recover_state(
	const uint32_t *const msg1,
	const uint32_t *const msg2,
	uint32_t *const state1,
	uint32_t *const state2,
	const size_t i);

#endif
