#include "translation-unit.h"
#include <cstdlib>

//===---------------------------------------------------------------------====//
// GuestBlock implementation
//===---------------------------------------------------------------------====//
void GuestBlock::AddGuestInst(GuestInst *Inst) {
    GuestInsts.push_back(Inst);
}

//===---------------------------------------------------------------------====//
// TranslationUnit implementation
//===---------------------------------------------------------------------====//
TranslationUnit::~TranslationUnit() {
    GuestBlocks.clear();
}

GuestBlock *TranslationUnit::CreateAndAddGuestBlock() {
    GuestBlocks.emplace_back();
    return &GuestBlocks.back();
}

void TranslationUnit::dump() {
    // TODO
    exit(0);
}

//===---------------------------------------------------------------------====//
// Glboal TranslationUnit definition and operations for C code
//===---------------------------------------------------------------------====//
static TranslationUnit GlobalTU;

TranslationUnit *tu_get(void) {
    return &GlobalTU;
}

void tu_init(TranslationUnit *TU) {
    TU->~TranslationUnit();
}
