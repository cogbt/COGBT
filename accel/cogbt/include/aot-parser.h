#ifndef AOT_PARSER_H
#define AOT_PARSER_H

#include "llvm-translator.h"
#include <memory>
using CodeCacheInfo = LLVMTranslator::CodeCacheInfo;

//===----------------------------------------------------------------------===//
// AOT parser definition
//===----------------------------------------------------------------------===//
class AOTParser {
private:
    LLVMContext Ctx;           ///< LLVMContext used by Module
    std::unique_ptr<Module> M; ///< Module used by ExecutionEngine
    CodeCacheInfo CodeCache;   ///< Code cache of aot after relocation
    ExecutionEngine *EE;       ///< ExecutionEngine used for relocation

    std::vector<std::string> FuncNames;  ///< All function symbols of AOT
    std::vector<std::string> UndefNames; ///< All undefined symbols

public:
    AOTParser(uintptr_t CacheBegin, size_t CacheSize, const char *AOT);

    /// AddGlobalMapping - Adding an external symbol address to ExecutionEngine
    void AddGlobalMapping(std::string Name, uint64_t Address);

    /// ResolveSymbols - Resolve all external symbols of AOT file.
    void ResolveSymbols();

    /// ParseNextFunction - Parse all functions of AOT and return their native
    /// code address. If all functions are parsed, return NULL instead.
    void *ParseNextFunction(uint64_t *pc, size_t *tu_size);

    /// GetCurrentCodeCachePtr - Get the first free address of memory manager
    /// code cache.
    void *GetCurrentCodeCachePtr();
};
#endif
