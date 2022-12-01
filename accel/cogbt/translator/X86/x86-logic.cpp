#include "x86-translator.h"

void X86Translator::translate_xor(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateXor(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_and(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateAnd(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_or(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateOr(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_sar(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }
    Value *Dest = Builder.CreateAShr(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }
    Value *Dest = Builder.CreateLShr(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shl(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }
    Value *Dest = Builder.CreateShl(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shld\n";
    exit(-1);
}
void X86Translator::translate_shlx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shlx\n";
    exit(-1);
}
void X86Translator::translate_shrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shrd\n";
    exit(-1);
}
void X86Translator::translate_shrx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shrx\n";
    exit(-1);
}

void X86Translator::translate_neg(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateNeg(Src);
    StoreOperand(Dest, InstHdl.getOpnd(0));
    CalcEflag(Inst, Dest, Src, nullptr);
}

void X86Translator::translate_nop(GuestInst *Inst) {}

void X86Translator::translate_not(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateNot(Src);
    StoreOperand(Dest, InstHdl.getOpnd(0));
}

void X86Translator::translate_bsf(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = LoadOperand(InstHdl.getOpnd(1));
    Value *isZero = Builder.CreateICmpEQ(Src, ConstInt(Src->getType(), 0));
    Value *Src64 = Src;
    if (Src->getType()->getIntegerBitWidth() != 64)
        Builder.CreateZExt(Src, Int64Ty);
    FunctionType *FuncTy = FunctionType::get(Int64Ty, Int64Ty, false);
    Value *Idx = CallFunc(FuncTy, "llvm.cttz.i64", Src64);
    if (Src->getType()->getIntegerBitWidth() != 64)
        Idx = Builder.CreateTrunc(Idx, Src->getType());

    Dest = Builder.CreateSelect(isZero, Dest, Idx);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Src, nullptr, nullptr);
}

void X86Translator::translate_bsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bsr\n";
    exit(-1);
}
void X86Translator::translate_bswap(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bswap\n";
    exit(-1);
}
