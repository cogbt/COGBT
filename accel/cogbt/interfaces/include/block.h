#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <capstone.h>
#include "cogbt.h"

void cogbt_block_init(void);
int block_gen_code(uint64_t pc, int max_insns, LLVMTranslator *translator,
                   void **code_cache, int *insn_cnt);
bool guest_inst_is_terminator(cs_insn *insn);

#endif
