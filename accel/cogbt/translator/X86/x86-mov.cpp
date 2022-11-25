#include "x86-translator.h"

void X86Translator::translate_lea(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *V = CalcMemAddr(InstHdl.getOpnd(0));
    StoreOperand(V, InstHdl.getOpnd(1));
}
