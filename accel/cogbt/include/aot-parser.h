#ifndef AOT_PARSER_H
#define AOT_PARSER_H

#include "llvm-translator.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugLine.h"
#include <memory>
using CodeCacheInfo = LLVMTranslator::CodeCacheInfo;

//===----------------------------------------------------------------------===//
// AOT function information recorder definition
//===----------------------------------------------------------------------===//
class FunctionInfo {
    std::string Name;            ///< Functin Name
    uint64_t BeginAddr, EndAddr; ///< Function address range[BeginAddr, EndAddr)
    int LinkOffset[2];           ///< Link instruction offset to entry.

public:
    FunctionInfo(std::string Name, uint64_t Address, size_t size)
        : Name(Name), BeginAddr(Address), EndAddr(Address + size) {
        LinkOffset[0] = LinkOffset[1] = -1;
    }

    /// Implement custom operator to support compare and sort.
    bool operator<(const FunctionInfo &F) const {
        assert(EndAddr <= F.BeginAddr || BeginAddr >= F.EndAddr);
        return BeginAddr < F.BeginAddr;
    }

    /// Member accessor.
    std::string getName() { return Name; }
    uint64_t getBeginAddr() { return BeginAddr; }
    uint64_t getEndAddr() { return EndAddr; }
    int &getLinkOffset(int idx) {
        assert(idx == 1 || idx == 0);
        return LinkOffset[idx];
    }
};

//===----------------------------------------------------------------------===//
// AOT parser definition
//===----------------------------------------------------------------------===//
class AOTParser {
private:
    LLVMContext Ctx;           ///< LLVMContext used by Module
    std::unique_ptr<Module> M; ///< Module used by ExecutionEngine
    CodeCacheInfo CodeCache;   ///< Code cache of aot after relocation
    ExecutionEngine *EE;       ///< ExecutionEngine used for relocation

    /* std::vector<std::string> FuncNames;  ///< All function symbols of AOT */
    std::vector<FunctionInfo> FuncInfos; ///< All functions of AOT
    std::vector<std::string> UndefNames; ///< All undefined symbols

    const DWARFDebugLine::LineTable  *LT;

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

    /// HandleAllLinkSlots - Hanle all TranslationUnit link slots
    void HandleAllLinkSlots();

private:
    /// RegisterLinkSlot - Register link slot information into corresbonding
    /// FunctionInfo.
    void RegisterLinkSlot(uint64_t HostAddr, int ExitID, int Type);

    /// FindFunctionInfo - Find the function info of the given AOT instruction
    /// address. Return the index of FuncInfos
    int FindFunctionInfo(uint64_t HostAddr);
};
#endif
