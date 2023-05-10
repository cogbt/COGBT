#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <capstone.h>
#include "cogbt.h"

#ifdef __cplusplus
extern "C" {
#endif

void cogbt_block_init(void);
int block_gen_code(uint64_t pc, int max_insns, LLVMTranslator *translator,
                   void **code_cache, int *insn_cnt);
bool guest_inst_is_terminator(cs_insn *insn);
void block_tu_file_parse(const char *pf);
void tb_aot_gen(const char *pf);

#ifdef __cplusplus
}
#endif

#endif
