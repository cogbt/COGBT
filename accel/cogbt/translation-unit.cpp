#include "translation-unit.h"
#include "x86-inst-handler.h"
#include <cstdlib>

//===---------------------------------------------------------------------====//
// GuestBlock implementation
//===---------------------------------------------------------------------====//
void GuestBlock::AddGuestInst(GuestInst Inst) {
    GuestInsts.emplace_back(Inst);
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
    fprintf(stderr, "================ TU details ==============\n");
    fprintf(stderr, "TUEntry : 0x%lx\n", GetTUEntry());
    fprintf(stderr, "TUSize : %ld\n", GetTUPCSize());
    for (auto bit = this->begin(); bit != this->end(); ++bit) {
        for (auto iit = bit->begin(); iit != bit->end(); ++iit) {
            GuestInst *inst = &(*iit);
            X86InstHandler InstHdl(inst);
            fprintf(stderr, "0x%lx  %s\t%s\n", InstHdl.getPC(),
                    InstHdl.getMnemonic(), InstHdl.getOPStr());
        }
    }
}

//===---------------------------------------------------------------------====//
// Glboal TranslationUnit definition and operations for C code
//===---------------------------------------------------------------------====//
static TranslationUnit GlobalTU;

TranslationUnit *tu_get(void) {
    return &GlobalTU;
}

void tu_init(TranslationUnit *TU) {
    TU->Clear();
}

void guest_block_add_inst(GuestBlock *Block, GuestInst Inst) {
    Block->AddGuestInst(Inst);
}

GuestBlock *guest_tu_create_block(TranslationUnit *TU) {
    return  TU->CreateAndAddGuestBlock();
}
