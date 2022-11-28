#include "x86-translator.h"

void X86Translator::translate_setae(GuestInst *Inst) {
    // Set if CF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), CF_SHIFT));
    Value *Val = Builder.CreateAnd(CF, ConstInt(CF->getType(), 1));
    Val = Builder.CreateSub(ConstInt(Val->getType(), 1), Val);
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seta(GuestInst *Inst) {
    // Set if CF == 0 AND ZF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), CF_SHIFT));
    Value *ZF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Value *Val = Builder.CreateOr(CF, ZF);
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    Val = Builder.CreateICmpEQ(Val, ConstInt(Val->getType(), 0));
    Val = Builder.CreateZExt(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setbe(GuestInst *Inst) {
    // Set if CF == 1 OR ZF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), CF_SHIFT));
    Value *ZF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Value *Val = Builder.CreateOr(CF, ZF);
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setb(GuestInst *Inst) {
    // Set if CF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Val = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), CF_SHIFT));
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sete(GuestInst *Inst) {
    // Set if ZF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Val = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setge(GuestInst *Inst) {
    // Set if SF == OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *Val = Builder.CreateICmpEQ(SF, OF);
    Val = Builder.CreateZExt(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setg(GuestInst *Inst) {
    // ZF == 0 and SF == OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    ZF = Builder.CreateAnd(ZF, ConstInt(ZF->getType(), 1));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *Val = Builder.CreateOr(ZF, Builder.CreateXor(SF, OF));
    Val = Builder.CreateICmpEQ(Val, ConstInt(Val->getType(), 0));
    Val = Builder.CreateZExt(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setle(GuestInst *Inst) {
    // ZF == 1 Or SF != OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    ZF = Builder.CreateAnd(ZF, ConstInt(ZF->getType(), 1));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *Val = Builder.CreateOr(ZF, Builder.CreateXor(SF, OF));
    Val = Builder.CreateICmpNE(Val, ConstInt(Val->getType(), 0));
    Val = Builder.CreateZExt(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *Val = Builder.CreateICmpNE(SF, OF);
    Val = Builder.CreateZExt(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setne(GuestInst *Inst) {
    // ZF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), ZF_SHIFT));
    Value *Val = Builder.CreateAnd(ZF, ConstInt(ZF->getType(), 1));
    Val = Builder.CreateSub(ConstInt(Val->getType(), 1), Val);
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setno(GuestInst *Inst) {
    // OF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    Value *Val = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Val = Builder.CreateSub(ConstInt(Val->getType(), 1), Val);
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setnp(GuestInst *Inst) {
    // PF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *PF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), PF_SHIFT));
    Value *Val = Builder.CreateAnd(PF, ConstInt(PF->getType(), 1));
    Val = Builder.CreateSub(ConstInt(Val->getType(), 1), Val);
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Value *Val = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    Val = Builder.CreateSub(ConstInt(Val->getType(), 1), Val);
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seto(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Val = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT));
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setp(GuestInst *Inst) {
    // PF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Val = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), PF_SHIFT));
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sets(GuestInst *Inst) {
    // SF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Val = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT));
    Val = Builder.CreateAnd(Val, ConstInt(Val->getType(), 1));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

