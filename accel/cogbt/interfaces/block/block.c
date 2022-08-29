#include "block.h"
#include "capstone.h"
#include "translation-unit.h"
#include <assert.h>

#define DISASSEMBLE_DEBUG

/* capsthone handler, will be used in some cs API. */
csh handle;
TranslationUnit *global_tu;

void cogbt_block_init(void) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    global_tu = tu_get();
    tu_init(global_tu);
}

static bool guest_inst_is_terminator(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           cs_insn_group(handle, insn, CS_GRP_CALL);
#if 0
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE);
#endif
}

int block_gen_code(uint64_t pc, void *code_cache, int max_insns,
                   int *insn_cnt) {
    cs_insn **insns = calloc(max_insns + 1, sizeof(cs_insn *));
    *insn_cnt = 0;

    for (int i = 0; i < max_insns; i++) {
        int res = cs_disasm(handle, (const uint8_t *)pc, 15, pc, 1, insns + i);
        if (res == 0) {
            // TODO
            printf("Error! Disassemble inst at 0x%lx failed\n", pc);
            exit(-1);
        }

#ifdef DISASSEMBLE_DEBUG
        printf("0x%lx  %s\t%s\n", insns[i]->address, insns[i]->mnemonic,
               insns[i]->op_str); // debug
#endif
        ++*insn_cnt;

        // Check wether we have reached the terminator of a basic block
        if (guest_inst_is_terminator(insns[i]))
            break;

        // Update pc of next instruction
        pc = insns[i]->address + insns[i]->size;
    }

    /* Register all guest instruction to TranslationUnit */

    /* Compile this TranslationUnit */

    /* Free all cs_insn allocated by capstone */
    for (int i = 0; i < *insn_cnt; i++) {
        cs_free(insns[i], 1);
    }
    free(insns);
    return 0;
}
