#include "x86-translator.h"

void X86Translator::translate_xor(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateXor(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(0));
    // CalcEflag(Inst, Dest, Src0, Src1);
}
