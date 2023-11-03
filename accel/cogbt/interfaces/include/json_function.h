#ifndef JSON_FUNCTION_H
#define JSON_FUNCTION_H

#ifdef __cplusplus

#include <cstdint>
#include <capstone.h>
#include "cogbt.h"
#include <string>
#include <vector>
#include <set>
#include <memory>
using std::string;
using std::vector;
using std::set;
using std::unique_ptr;
using std::shared_ptr;

#else

#include <stdint.h>
#include <capstone.h>
#include "cogbt.h"

#endif // include headfile

//===---------------------------------------------------------------------====//
// JsonBlock is used to record basic block info in a json file.
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class JsonBlock {
    uint64_t Entry;  ///< Entry point of basic block.
    uint64_t Exit;   ///< Exit point of basic blcok.
    uint64_t InsNum; ///< Block instruction nums.
public:
    JsonBlock(uint64_t Entry, uint64_t Exit, uint64_t InsNum)
        : Entry(Entry), Exit(Exit), InsNum(InsNum) {}
    uint64_t getEntry() const { return Entry; }
    uint64_t getExit() const { return Exit; }
    uint64_t getInsNum() const { return InsNum; }

    bool operator<(const JsonBlock &JB) const {
        return Entry < JB.Entry || (Entry == JB.Entry && Exit < JB.Exit);
    }
};
#else
typedef struct JsonBlock JsonBlock;
#endif  // class JsonBlock

//===---------------------------------------------------------------------====//
// JsonFunc is used to record function info in a json file.
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class JsonFunc {
    string Name;
    uint64_t EntryPoint, ExitPoint = -1;
    uint64_t FuncBoundary = -1;     // guest function range
    vector<uint64_t> BlockStrs;
    vector<JsonBlock> Blocks;
public:
    JsonFunc(string Name, uint64_t EntryPoint, vector<uint64_t> &BS)
        : Name(Name), EntryPoint(EntryPoint), BlockStrs(std::move(BS)) {
        Blocks.clear();
    }
    JsonFunc(string Name, uint64_t EntryPoint, uint64_t FuncBoundary)
        : Name(Name), EntryPoint(EntryPoint), FuncBoundary(FuncBoundary) {}

    string& getName() { return Name; }
    uint64_t getEntryPoint() { return EntryPoint; }
    uint64_t getExitPoint() { return ExitPoint; }
    uint64_t getFuncBoundary() { return FuncBoundary; }
    void setEntryPoint(uint64_t EntryPoint) { this->EntryPoint = EntryPoint; }
    void setExitPoint(uint64_t ExitPoint) { this->ExitPoint = ExitPoint; }
    void setFuncBoundary(uint64_t FuncBoundary) {
        this->FuncBoundary = FuncBoundary;
    }
    vector<uint64_t> &getBlockStrs() { return BlockStrs; }
    void addBlockStrs(uint64_t BlockStr) { BlockStrs.push_back(BlockStr); }

    ///  formalize - Formalization JsonFunc, this involves two steps:
    ///     1. Sort BlockStrs
    ///     2. Calculate Blocks by using the sorted BlockStrs as the entry point
    ///        of JsonBlock.
    /// Note:
    ///     1. The exit point of each JsonBlock is either a termination instruction
    ///        or the entry point of next JsonBlock.
    ///     2. The exit point of the last JsonBlock cannot exceed `Boundary`.
    void formalize(uint64_t Boundary);

    void addJsonBlock(const JsonBlock &JB) { Blocks.push_back(JB); }
    void addJsonBlocks(const vector<JsonBlock> &JBs) {
        for (auto JB : JBs)
            addJsonBlock(JB);
    }

    using Iterator = std::vector<JsonBlock>::iterator;
    Iterator begin() { return Blocks.begin(); }
    Iterator end() { return Blocks.end(); }

    using Name_Iterator = vector<uint64_t>::iterator;
    using Name_Reverse_Iterator = vector<uint64_t>::reverse_iterator;
    Name_Iterator name_begin() { return BlockStrs.begin(); }
    Name_Iterator name_end() { return BlockStrs.end(); }
    Name_Iterator name_erase(Name_Iterator it, Name_Iterator et) {
        return BlockStrs.erase(it, et);
    }
    Name_Reverse_Iterator name_rbegin() { return BlockStrs.rbegin(); }
    Name_Reverse_Iterator name_rend() { return BlockStrs.rend(); }

    bool operator<(const JsonFunc &JF) const {
        return EntryPoint < JF.EntryPoint;
    }

    void dump(FILE *ff) const;
};
#else
typedef struct JsonFunc JsonFunc;
#endif  // class JsonFunc

//===---------------------------------------------------------------------====//
// BitMap is a simple bitmap implementation.
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class BitMap {
    vector<uint64_t> bm;
public:
    BitMap() = delete;
    BitMap(size_t NumElements) {
        bm.resize((NumElements + 63) >> 6, 0);
    }

    void set(unsigned idx) {
        assert(idx < (bm.size() << 6));
        bm[idx / 64] |= 1 << (idx % 64);
    }

    bool test(unsigned idx) {
        assert(idx < (bm.size() << 6));
        return (bm[idx / 64] >> (idx % 64)) & 1;
    }
};
#else
typedef struct BitMap BitMap;
#endif  // class BitMap


#ifdef __cplusplus
extern "C" {
#endif

/// cogbt_tu_init - Initialze cogbt tu mode.
void cogbt_tu_init(void);

/// func_tu_parse - Parse tu translation unit file,
/// include json, path file.
void func_tu_parse(const char *pf);

/// aot_gen - Generate final AOT.
void func_aot_gen(void);

#ifdef __cplusplus
}
#endif

#endif  // JSON_FUNCTION_H
