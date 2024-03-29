#ifndef COGBT_H
#define COGBT_H

#include "qemu/osdep.h"
#include "translation-unit.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct LLVMTranslator LLVMTranslator;
typedef struct AOTParser AOTParser;

LLVMTranslator *create_llvm_translator(uintptr_t cache_ptr, size_t cache_size);
void gen_prologue(LLVMTranslator *translator);
void gen_epilogue(LLVMTranslator *translator);
uint8_t *llvm_compile(LLVMTranslator *translator, bool use_optimizer);
void free_llvm_translator(LLVMTranslator *translator);

void llvm_initialize(LLVMTranslator *translator);
void llvm_finalize(LLVMTranslator *translator);
void llvm_set_tu(LLVMTranslator *translator, TranslationUnit *tu);
void llvm_translate(LLVMTranslator *translator);
size_t llvm_get_code_size(LLVMTranslator *translator);

bool debug_guest_inst(LLVMTranslator *translator);
bool debug_cpu_state(LLVMTranslator *translator);

AOTParser *create_aot_parser(uintptr_t cache_ptr, size_t cache_size,
                             const char *aot);
void add_global_mapping(AOTParser *parser, const char *Name, uint64_t address);
void free_aot_parser(AOTParser *parser);
void *parse_prologue(AOTParser *parser);
void *parse_epilogue(AOTParser *parser);
void *parse_next_function(AOTParser *parser, uint64_t *pc, size_t *tu_size,
                          size_t link_slots_offsets[2]);
void do_link(AOTParser *parser);
void *get_current_code_cache_ptr(AOTParser *parser);
void resolve_all_symbols(AOTParser *parser);

#ifdef CONFIG_COGBT_JMP_CACHE
void cogbt_jmp_cache_init(uint64_t start_code, uint64_t end_code);
void cogbt_jmp_cache_add(uint64_t target_pc, uint64_t host_pc);
void cogbt_jmp_cache_free(void);
#endif

enum RUNNING_MODE {
    JIT     = 0 ,
    TB_AOT      ,
    TU_AOT      ,
    TRACE_AOT   ,
    FUNCTION_AOT,
    AOT_NUMBER
};


#ifdef __cplusplus
}
#endif

#endif
