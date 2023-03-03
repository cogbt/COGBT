#ifndef TRANSLATION_UNIT_H
#define TRANSLATION_UNIT_H

#ifdef __cplusplus

#include <vector>
#include <cstdint>
#include <cstddef>
#include <cassert>
#include "capstone.h"
using std::vector;
using GuestInst = cs_insn;
using GuestPC = uint64_t;

#else

#include <stdint.h>
#include <assert.h>
typedef struct cs_insn GuestInst;
typedef uint64_t GuestPC;

#endif // include headfile

//===---------------------------------------------------------------------====//
// GuestBlock definition
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class GuestBlock {
    vector<GuestInst *> GuestInsts;
public:
    void AddGuestInst(GuestInst *Inst);

    /// All APIs for GuestInst should be registered below
    /// GetBlockEntry - Get block entry pc.
    uint64_t GetBlockEntry() {
        assert(!GuestInsts.empty() && "Block shouldn't be empty!");
        return GuestInsts[0]->address;
    }

    /// GetBlockPCSize - Get guest block pc size(last pc - first pc).
    size_t GetBlockPCSize() {
        assert(!GuestInsts.empty() && "Block shouldn't be empty!");
        return GuestInsts.back()->address + GuestInsts.back()->size -
               GetBlockEntry();
    }

    /// @name All APIs about iterators.
    using iteraotr = vector<GuestInst *>::iterator;
    using reverse_iterator = vector<GuestInst *>::reverse_iterator;

    iteraotr begin() { return GuestInsts.begin(); }
    iteraotr end() { return GuestInsts.end(); }
    reverse_iterator rbegin() { return GuestInsts.rbegin(); }
    reverse_iterator rend() { return GuestInsts.rend(); }
    size_t size() { return GuestInsts.size(); }
    bool empty() { return GuestInsts.empty(); }
};
#else
typedef struct GuestBlock GuestBlock;
#endif // class GuestBlock

//===---------------------------------------------------------------------====//
// TranslationUnit definition
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class TranslationUnit {
    vector<GuestBlock> GuestBlocks;

public:
    ~TranslationUnit();

    /// CreateAndAddGuestBlock - Create a GuestBlock in this TU and return its
    /// address.
    GuestBlock *CreateAndAddGuestBlock();

    /// Clear - Clear all guest blocks in this TU.
    void Clear() { GuestBlocks.clear(); }

    /// dump - Show all GuestInstructions in this TU.
    void dump(void);

    /// GetTUEntry - Get the first pc of TU.
    uint64_t GetTUEntry() {
        if (GuestBlocks.empty()) {
            exit(-1);
        }
        return (*GuestBlocks[0].begin())->address;
    }

    /// GetTUExit - Get the last pc of TU.
    uint64_t GetTUExit() {
        if (GuestBlocks.empty()) {
            exit(-1);
        }
        return (*GuestBlocks.rbegin()->rbegin())->address;
    }

    /// GetTUPCSize - Get size of target code for this TranslationUnit.
    size_t GetTUPCSize() {
        assert(!GuestBlocks.empty() && "TranslationUnit shouldn't be empty!");
        size_t num = 0;
        for (GuestBlock &B : GuestBlocks) {
            num += B.GetBlockPCSize();
        }
        return num;
    }

    /// @name All interfaces about iterators.
    using iterator = vector<GuestBlock>::iterator;
    using reverse_iterator = vector<GuestBlock>::reverse_iterator;

    iterator begin() { return GuestBlocks.begin(); }
    iterator end() { return GuestBlocks.end(); }
    reverse_iterator rbegin() { return GuestBlocks.rbegin(); }
    reverse_iterator rend() { return GuestBlocks.rend(); }
    size_t size() { return GuestBlocks.size(); }
    bool empty() { return GuestBlocks.empty(); }
};
#else
typedef struct TranslationUnit TranslationUnit;
#endif // class TranslationUnit


//===---------------------------------------------------------------------====//
// C++ function wrappers called by C code
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
extern "C" {
#endif

TranslationUnit *tu_get(void);
void tu_init(TranslationUnit *TU);

void guest_block_add_inst(GuestBlock *Block, GuestInst *Inst);
GuestBlock *guest_tu_create_block(TranslationUnit *TU);

#ifdef __cplusplus
}
#endif

#endif // TRANSLATION_UNIT_H
