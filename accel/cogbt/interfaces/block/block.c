#include "block.h"
#include "capstone.h"
#include "translation-unit.h"
#include <assert.h>

#define DISASSEMBLE_DEBUG

/* capsthone handler, will be used in some cs API. */
static csh handle;
static TranslationUnit *global_tu;

void cogbt_block_init(void) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    global_tu = tu_get();
    tu_init(global_tu);
}

bool guest_inst_is_terminator(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_INT);
#if 0
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE);
#endif
}

int block_gen_code(uint64_t pc, int max_insns, LLVMTranslator *translator,
                   void **code_cache, int *insn_cnt) {
    cs_insn **insns = calloc(max_insns + 1, sizeof(cs_insn *));
    *insn_cnt = 0;

    if (debug_guest_inst(translator)) {
        fprintf(stderr, "+------------------------------------------------+\n");
        fprintf(stderr, "|                 Guest Block                    |\n");
        fprintf(stderr, "+------------------------------------------------+\n");
    }
    for (int i = 0; i < max_insns; i++) {
        int res = cs_disasm(handle, (const uint8_t *)pc, 15, pc, 1, insns + i);
        if (res == 0) {
            // TODO
            printf("Error! Disassemble inst at 0x%lx failed\n", pc);
            exit(-1);
        }

        if (debug_guest_inst(translator)) {
            fprintf(stderr, "0x%lx  %s\t%s\n", insns[i]->address,
                    insns[i]->mnemonic, insns[i]->op_str);
        }
        ++*insn_cnt;

        // Check wether we have reached the terminator of a basic block
        if (guest_inst_is_terminator(insns[i]))
            break;

        // Update pc of next instruction
        pc = insns[i]->address + insns[i]->size;
    }

    /* Register all guest instruction to TranslationUnit */
    TranslationUnit *tu = tu_get();
    tu_init(tu);
    GuestBlock *block = guest_tu_create_block(tu);
    for (int i = 0; i < *insn_cnt; i++) {
        guest_block_add_inst(block, insns[i]);
    }

    /* Compile this TranslationUnit */
    size_t llvm_code_size_before = llvm_get_code_size(translator);
    llvm_initialize(translator);
    llvm_set_tu(translator, tu);
    llvm_translate(translator);
    *(uint32_t **)code_cache = (uint32_t *)llvm_compile(translator, true);
    size_t llvm_code_size_after = llvm_get_code_size(translator);

    /* Free all cs_insn allocated by capstone */
    for (int i = 0; i < *insn_cnt; i++) {
        cs_free(insns[i], 1);
    }
    free(insns);
    return llvm_code_size_after - llvm_code_size_before;
}
