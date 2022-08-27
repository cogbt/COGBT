#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>

void cogbt_block_init(void);
int block_gen_code(uint64_t pc, void *code_cache, int max_insns, int *insn_cnt);

#endif
