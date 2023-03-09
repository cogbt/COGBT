#ifndef AOT_PARSER_H
#define AOT_PARSER_H

/* #include "qemu/osdep.h" */
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
    uint64_t EntryPC;            ///< TranslationUnit entry pc
    uint64_t BeginAddr, EndAddr; ///< Function address range[BeginAddr, EndAddr)
    uint64_t LoadAddr;           ///< The address loaded in memory.
    /* int LinkOffset[2];           ///< Link instruction offset to entry. */
    vector<int> LinkOffset;      ///< Link instruction offset to entry.

public:
    FunctionInfo(std::string Name, uint64_t Address, size_t size)
        : Name(Name), EntryPC(0), BeginAddr(Address), EndAddr(Address + size),
          LoadAddr(0), LinkOffset(8, -1) {
        /* LinkOffset[0] = LinkOffset[1] = -1; */
    }

    /// Implement custom operator to support compare and sort.
    bool operator<(const FunctionInfo &F) const {
        assert(EndAddr <= F.BeginAddr || BeginAddr >= F.EndAddr);
        return BeginAddr < F.BeginAddr;
    }

    /// Member accessor.
    std::string getName() { return Name; }
    uint64_t &getBeginAddr() { return BeginAddr; }
    uint64_t &getEndAddr() { return EndAddr; }
    uint64_t &getLoadAddr() { return LoadAddr; }
    uint64_t &getEntryPC() { return EntryPC; }
    int &getLinkOffset(int idx) {
        /* assert(idx == 1 || idx == 0); */
        // LinkOffset starts from 0, but idx(DWARF line number) starts from 1.
        /* idx = idx - 1; */
        if (idx >= (int) LinkOffset.size()) {
#ifdef CONFIG_COGBT_DEBUG
            fprintf(stderr, "%s has %d ExitPoint\n", Name.c_str(), idx);
#endif
            LinkOffset.resize(idx+1, -1);
        }
        return LinkOffset[idx];
    }
    int getLinkSlotNumber() { return (int) LinkOffset.size(); }
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

    /* const DWARFDebugLine::LineTable  *LT; */

public:
    AOTParser(uintptr_t CacheBegin, size_t CacheSize, const char *AOT);

    /// AddGlobalMapping - Adding an external symbol address to ExecutionEngine
    void AddGlobalMapping(std::string Name, uint64_t Address);

    /// ResolveSymbols - Resolve all external symbols of AOT file.
    void ResolveSymbols();

    /// ParseNextFunction - Parse all functions of AOT and return their native
    /// code address. If all functions are parsed, return NULL instead.
    void *ParseNextFunction(uint64_t *pc, size_t *tu_size,
                            size_t link_slots_offsets[2]);

    /// ParsePrologue - Extract prologue native code and return it's address. If
    /// there isn't a prologue function, return nullptr instead.
    void *ParsePrologue();
    /// ParseEpilogue - Extract epilogue native code and return it's address. If
    /// there isn't a prologue function, return nullptr instead.
    void *ParseEpilogue();

    /// GetCurrentCodeCachePtr - Get the first free address of memory manager
    /// code cache.
    void *GetCurrentCodeCachePtr();

    /// DoLink - Hanle all TranslationUnit link.
    void DoLink();

private:
    /// RegisterLinkSlot - Register link slot information into corresbonding
    /// FunctionInfo.
    void RegisterLinkSlot(uint64_t HostAddr, int ExitID, int Type);

    /// FindFunctionInfo - Find the function info of the given AOT instruction
    /// address. Return the index of FuncInfos
    int FindFunctionInfo(uint64_t HostAddr);

    /// FindFunctionInfoAtPC - Find function info with EntryPC equals pc.
    int FindFunctionInfoAtPC(uint64_t pc);
};
#endif
