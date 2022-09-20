#include <stdint.h>
#include <stddef.h>
#include "cogbt.h"
#include "x86-translator.h"

LLVMTranslator *create_llvm_translator(uintptr_t CacheBegin, size_t CacheSize) {
    return new X86Translator(CacheBegin, CacheSize);
}

void gen_prologue(LLVMTranslator *translator) {
    translator->GenPrologue();
}

void gen_epilogue(LLVMTranslator *translator) {
    translator->GenEpilogue();
}

uint8_t *llvm_compile(LLVMTranslator *translator, bool use_optimizer) {
    return translator->Compile(use_optimizer);
}

void free_llvm_translator(LLVMTranslator *translator) {
    delete translator;
}
