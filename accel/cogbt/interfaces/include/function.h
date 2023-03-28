#ifndef FUNCTION_H
#define FUNCTION_H

#ifdef __cplusplus

#include <cstdint>
#include <capstone.h>
#include "cogbt.h"
#include <string>
#include <vector>
#include <set>
using std::string;
using std::vector;
using std::set;

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
    set<uint64_t> BlockStrs;
    set<JsonBlock> Blocks;
public:
    JsonFunc(string Name, uint64_t EntryPoint, set<uint64_t> &BS)
        : Name(Name), EntryPoint(EntryPoint), BlockStrs(std::move(BS)) {
        Blocks.clear();
    }

    string& getName() { return Name; }
    uint64_t getEntryPoint() { return EntryPoint; }
    uint64_t getExitPoint() { return ExitPoint; }
    void setEntryPoint(uint64_t EntryPoint) { this->EntryPoint = EntryPoint; }
    void setExitPoint(uint64_t ExitPoint) { this->ExitPoint = ExitPoint; }
    set<uint64_t> &getBlockStrs() { return BlockStrs; }
    void addBlockStrs(uint64_t BlockStr) { BlockStrs.insert(BlockStr); }

    void formalize(uint64_t Boundary);

    void addJsonBlock(const JsonBlock &JB) { Blocks.insert(JB); }
    void addJsonBlocks(const set<JsonBlock> &JBs) {
        for (auto JB : JBs)
            addJsonBlock(JB);
    }

    using Iterator = std::set<JsonBlock>::iterator;
    Iterator begin() { return Blocks.begin(); }
    Iterator end() { return Blocks.end(); }

    using Name_Iterator = set<uint64_t>::iterator;
    using Name_Reverse_Iterator = set<uint64_t>::reverse_iterator;
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

    void dump(FILE *ff) const {
        fprintf(ff, "\"0x%lx\": {\n", EntryPoint);
        fprintf(ff, "\t\"Name\": \"%s\",\n", Name.c_str());
        fprintf(ff, "\t\"EntryPoint\": \"0x%lx\",\n", EntryPoint);
        if (ExitPoint)
            fprintf(ff, "\t\"ExitPoint\": \"0x%lx\",\n", ExitPoint);
        fprintf(ff, "\t\"Blocks\": [\n");
        for(set<JsonBlock>::iterator it = Blocks.begin();
                it != Blocks.end(); it++) {
            if (it == (--Blocks.end()))
                fprintf(ff, "\t\t\"[0x%lx, 0x%lx), %ld\"\n", it->getEntry(),
                    it->getExit(), it->getInsNum());
            else
                fprintf(ff, "\t\t\"[0x%lx, 0x%lx), %ld\",\n", it->getEntry(),
                    it->getExit(), it->getInsNum());
        }
        fprintf(ff, "\t]\n");
        fprintf(ff, "}\n");
    }
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

/// cogbt_function_init - Initialze cogbt function tu mode.
void cogbt_function_init(void);
/// cogbt_function_fini - Finalize cogbt function tu mode.
void cogbt_function_fini(void);

/// func_tu_parse - Parse function translation unit file,
/// include json, path file.
void func_tu_parse(const char *pf);

/// aot_gen - Generate final AOT.
void func_aot_gen(void);

#ifdef __cplusplus
}
#endif

#endif  // FUNCTION_H
