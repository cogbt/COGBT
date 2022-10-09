#include <stdint.h>
#include <stddef.h>
#include "cogbt.h"
#include "x86-translator.h"
#include "llvm/Support/TargetSelect.h"

LLVMTranslator *create_llvm_translator(uintptr_t CacheBegin, size_t CacheSize) {
    InitializeAllTargets();
    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllDisassemblers();
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

void llvm_initialize(LLVMTranslator *translator) {
    translator->InitializeModule();
}

void llvm_set_tu(LLVMTranslator *translator, TranslationUnit *tu) {
    translator->SetTU(tu);
}

void llvm_translate(LLVMTranslator *translator) {
    translator->Translate();
}

size_t llvm_get_code_size(LLVMTranslator *translator) {
    return translator->GetCurrentCodeSize();
}
