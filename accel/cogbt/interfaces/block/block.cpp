#include "string.h"
#include "errno.h"
#include "block.h"
#include "capstone.h"
#include "translation-unit.h"
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <iostream>
#include <vector>

#define DISASSEMBLE_DEBUG
using std::vector;

/* capsthone handler, will be used in some cs API. */
static csh handle;
static TranslationUnit *global_tu;
static vector<TranslationUnit *> TUs;

void cogbt_block_init(void) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    TUs.clear();
    global_tu = tu_get();
    tu_init(global_tu);
}

bool guest_inst_is_terminator(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_INT);
}

#define MAX_INSN 200
void block_tu_file_parse(const char *pf) {
    FILE *path = fopen(pf, "r");
    if (path == NULL) {
        fprintf(stderr, "%s: %s\n", pf, strerror(errno));
        exit(-1);
    }

    uint64_t pc;
    while (fscanf(path, "%lx", &pc) != EOF) {
        cs_insn **insns = (cs_insn **)calloc(MAX_INSN, sizeof(cs_insn *));
        int insn_cnt = 0;
        /* fprintf(stderr, "0x%lx\n", pc); */
        for (int i = 0; i < MAX_INSN; i++) {
            int res =
                cs_disasm(handle, (const uint8_t *)pc, 15, pc, 1, insns + i);
            if (res == 0) {
                // TODO
                printf("Error! Disassemble inst at 0x%lx failed\n", pc);
                exit(-1);
            }

            ++insn_cnt;

            // Check wether we have reached the terminator of a basic block
            if (guest_inst_is_terminator(insns[i]))
                break;

            // Update pc of next instruction
            pc = insns[i]->address + insns[i]->size;
        }
        insns = (cs_insn **)realloc(insns, sizeof(cs_insn *) * insn_cnt);

        // Register block in TU
        /* TranslationUnit *tu = tu_get(); */
        TranslationUnit *TU = new TranslationUnit();
        tu_init(TU);
        GuestBlock *block = guest_tu_create_block(TU);
        for (int i = 0; i < insn_cnt; i++) {
            guest_block_add_inst(block, insns[i]);
        }
        TUs.push_back(TU);
    }
}

void tb_aot_gen(const char *pf) {
    LLVMTranslator *Translator = create_llvm_translator(0, 0);
    llvm_initialize(Translator);
    for (TranslationUnit *TU: TUs) {
        llvm_set_tu(Translator, TU);
        llvm_translate(Translator);
        llvm_compile(Translator, true);
        delete TU;
    }
    llvm_finalize(Translator);
}

// JIT mode
int block_gen_code(uint64_t pc, int max_insns, LLVMTranslator *translator,
                   void **code_cache, int *insn_cnt) {
    cs_insn **insns = (cs_insn **)calloc(max_insns + 1, sizeof(cs_insn *));
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
    llvm_finalize(translator);
    *(uint32_t **)code_cache = (uint32_t *)llvm_compile(translator, true);
    size_t llvm_code_size_after = llvm_get_code_size(translator);

    /* Free all cs_insn allocated by capstone */
    for (int i = 0; i < *insn_cnt; i++) {
        cs_free(insns[i], 1);
    }
    free(insns);
    return llvm_code_size_after - llvm_code_size_before;
}
