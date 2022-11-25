#include "x86-translator.h"

void X86Translator::translate_lea(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *V = CalcMemAddr(InstHdl.getOpnd(0));
    StoreOperand(V, InstHdl.getOpnd(1));
}

void X86Translator::translate_movzx(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateZExt(Src0, GetOpndLLVMType(InstHdl.getOpnd(1)));
    StoreOperand(Dest, InstHdl.getOpnd(1));
}
