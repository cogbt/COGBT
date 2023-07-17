#ifndef TRANSLATION_UNIT_H
#define TRANSLATION_UNIT_H

#ifdef __cplusplus

#include <vector>
#include <cstdint>
#include <cstddef>
#include <cassert>
#include "capstone.h"
using std::vector;
using GuestPC = uint64_t;

#else

#include <stdint.h>
#include <assert.h>
typedef uint64_t GuestPC;

#endif // include headfile


#ifdef __cplusplus
class GuestInst {
private:
    vector<uint64_t> traceTargets;
public:
    cs_insn *guestInst;

    GuestInst(cs_insn* inst) : guestInst(inst) {}
    int getNumOfTraceTargets() { return traceTargets.size(); }
    void addTraceTarget(uint64_t target) { traceTargets.push_back(target); }
    bool searchTraceTarget(uint64_t target) {
        for (size_t i = 0; i < traceTargets.size(); ++i) {
            if (traceTargets[i] == target)
                return true;
        }
        return false;
    }
    uint64_t getTraceTarget(int index) {
        assert(index < (int) traceTargets.size());
        return traceTargets[index];
    }

};
#else
typedef struct GuestInst GuestInst;
#endif // class GuestInst

//===---------------------------------------------------------------------====//
// GuestBlock definition
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class GuestBlock {
    vector<GuestInst> GuestInsts;
public:
    void AddGuestInst(GuestInst Inst);

    /// All APIs for GuestInst should be registered below
    /// GetBlockEntry - Get block entry pc.
    uint64_t GetBlockEntry() {
        assert(!GuestInsts.empty() && "Block shouldn't be empty!");
        return GuestInsts[0].guestInst->address;
    }

    /// GetBlockPCSize - Get guest block pc size(last pc - first pc).
    size_t GetBlockPCSize() {
        assert(!GuestInsts.empty() && "Block shouldn't be empty!");
        return GuestInsts.back().guestInst->address +
            GuestInsts.back().guestInst->size - GetBlockEntry();
    }

    /// @name All APIs about iterators.
    using iteraotr = vector<GuestInst>::iterator;
    using reverse_iterator = vector<GuestInst>::reverse_iterator;

    iteraotr begin() { return GuestInsts.begin(); }
    iteraotr end() { return GuestInsts.end(); }
    reverse_iterator rbegin() { return GuestInsts.rbegin(); }
    reverse_iterator rend() { return GuestInsts.rend(); }
    size_t size() { return GuestInsts.size(); }
    bool empty() { return GuestInsts.empty(); }

    void addTraceTarget(uint64_t target) {
        // TODO: check whether GuestInsts.back() is a terminator instruction.
        GuestInsts.back().addTraceTarget(target);
    }
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
    int linkSlotNum;

public:
    /// Constructor - Due to DWARFDebugLine::ROW.Line are numbered beginning at
    /// 1, this linkSlotNum keep the same as it.
    TranslationUnit() { linkSlotNum = 0; }
    ~TranslationUnit();

    /// CreateAndAddGuestBlock - Create a GuestBlock in this TU and return its
    /// address.
    GuestBlock *CreateAndAddGuestBlock();

    /// Clear - Clear all guest blocks in this TU.
    void Clear() {
        GuestBlocks.clear();
        linkSlotNum = 0;
    }

    /// dump - Show all GuestInstructions in this TU.
    void dump(void);

    /// GetTUEntry - Get the first pc of TU.
    uint64_t GetTUEntry() {
        assert(!GuestBlocks.empty() && "GuestBlocks shouldn't be empty!");
        return GuestBlocks[0].begin()->guestInst->address;
    }

    /// GetTUExit - Get the last pc of TU.
    uint64_t GetTUExit() {
        assert(!GuestBlocks.empty() && "GuestBlocks shouldn't be empty!");
        return GuestBlocks.rbegin()->rbegin()->guestInst->address;
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

    bool operator<(TranslationUnit &TU) {
        return GetTUEntry() < TU.GetTUEntry();
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
    int IncLinkSlotNum() { linkSlotNum++; return linkSlotNum; }
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

void guest_block_add_inst(GuestBlock *Block, GuestInst Inst);
GuestBlock *guest_tu_create_block(TranslationUnit *TU);

#ifdef __cplusplus
}
#endif

#endif // TRANSLATION_UNIT_H
