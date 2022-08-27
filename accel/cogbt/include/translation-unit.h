#ifndef TRANSLATION_UNIT_H
#define TRANSLATION_UNIT_H

#ifdef __cplusplus

#include <vector>
#include <cstdint>
using std::vector;
using GuestInst = void;
using GuestPC = uint64_t;

#else

#include <stdint.h>
typedef void GuestInst;
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
    GuestBlock *CreateAndAddGuestBlock();
    void dump(void);
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
