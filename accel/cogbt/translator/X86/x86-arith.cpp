#include "x86-translator.h"

void X86Translator::translate_sub(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src1 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src0 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateSub(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}
