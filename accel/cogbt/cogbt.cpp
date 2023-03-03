#include <stdint.h>
#include <stddef.h>
#include "cogbt.h"
#include "x86-translator.h"
#include "aot-parser.h"
#include "llvm/Support/TargetSelect.h"

LLVMTranslator *create_llvm_translator(uintptr_t CacheBegin, size_t CacheSize) {
    InitializeAllTargets();
    InitializeAllTargetInfos();
    InitializeAllAsmParsers();
    InitializeAllAsmPrinters();
    InitializeAllTargetMCs();
    InitializeAllDisassemblers();
    InitializeNativeTarget();
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
    if (aotmode == 2) {
        translator->TranslateInitialize();
    }
}

void llvm_finalize(LLVMTranslator *translator) {
    translator->TranslateFinalize();
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

bool debug_guest_inst(LLVMTranslator *translator) {
    return translator->DBG.DebugGuestIns();
}

bool debug_cpu_state(LLVMTranslator *translator) {
    return translator->DBG.DebugCPUState();
}

AOTParser *create_aot_parser(uintptr_t cache_ptr, size_t cache_size,
                             const char *aot) {
    return new AOTParser(cache_ptr, cache_size, aot);
}

void add_global_mapping(AOTParser *parser, const char *name, uint64_t address) {
    parser->AddGlobalMapping(name, address);
}

void resolve_all_symbols(AOTParser *parser) {
    parser->ResolveSymbols();
}

void free_aot_parser(AOTParser *parser) {
    delete parser;
}

void *parse_prologue(AOTParser *parser) {
    return parser->ParsePrologue();
}

void *parse_epilogue(AOTParser *parser) {
    return parser->ParseEpilogue();
}

void *parse_next_function(AOTParser *parser, uint64_t *pc, size_t *tu_size,
                          size_t link_slots_offsets[2]) {
    return parser->ParseNextFunction(pc, tu_size, link_slots_offsets);
}

void *get_current_code_cache_ptr(AOTParser *parser) {
    return parser->GetCurrentCodeCachePtr();
}

void do_link(AOTParser *parser) {
    parser->DoLink();
}
