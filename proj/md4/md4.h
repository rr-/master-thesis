#ifndef MD4_H
#define MD4_H
#include <stdint.h>
#include <stddef.h>

uint32_t md4_f(uint32_t x, uint32_t y, uint32_t z);
uint32_t md4_g(uint32_t x, uint32_t y, uint32_t z);
uint32_t md4_h(uint32_t x, uint32_t y, uint32_t z);

extern const uint32_t md4_iv[4];
extern const uint32_t md4_shift[48];
extern const uint32_t md4_msg_index[48];
extern const uint32_t md4_add[48];

extern uint32_t (*md4_round_func[48])(
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
