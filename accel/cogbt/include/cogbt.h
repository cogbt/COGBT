#ifndef COGBT_H
#define COGBT_H

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

#ifdef __cplusplus
}
#endif

#endif
