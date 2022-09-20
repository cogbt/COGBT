#ifndef COGBT_H
#define COGBT_H

#include "translation-unit.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct LLVMTranslator LLVMTranslator;

LLVMTranslator *create_llvm_translator(uintptr_t cache_ptr, size_t cache_size);
void gen_prologue(LLVMTranslator *translator);
void gen_epilogue(LLVMTranslator *translator);
uint8_t *llvm_compile(LLVMTranslator *translator, bool use_optimizer);
void free_llvm_translator(LLVMTranslator *translator);

#ifdef __cplusplus
}
#endif

#endif
