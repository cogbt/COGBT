#ifndef TRANSLATION_UNIT_H
#define TRANSLATION_UNIT_H

#ifdef __cplusplus

#include <vector>
#include <cstdint>
#include <cstddef>
#include "capstone.h"
using std::vector;
using GuestInst = cs_insn;
using GuestPC = uint64_t;

#else

#include <stdint.h>
typedef struct cs_insn GuestInst;
typedef uint64_t GuestPC;

#endif // include headfile

//===---------------------------------------------------------------------====//
// GuestBlock definition
//===---------------------------------------------------------------------====//
#ifdef __cplusplus
class GuestBlock {
    vector<GuestInst *> GuestInsts;
    /// All APIs for GuestInst should be registered below
public:
    void AddGuestInst(GuestInst *Inst);

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

    /// dump - Show all GuestInstructions in this TU.
    void dump(void);

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
