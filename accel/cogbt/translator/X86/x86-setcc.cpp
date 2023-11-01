#include "x86-translator.h"

void X86Translator::translate_setae(GuestInst *Inst) {
    // Set if CF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjae");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seta(GuestInst *Inst) {
    // Set if CF == 0 AND ZF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setja");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setbe(GuestInst *Inst) {
    // Set if CF == 1 OR ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjbe");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setb(GuestInst *Inst) {
    // Set if CF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjb");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sete(GuestInst *Inst) {
    // Set if ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setje");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setge(GuestInst *Inst) {
    // Set if SF == OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjge");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setg(GuestInst *Inst) {
    // ZF == 0 and SF == OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjg");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setle(GuestInst *Inst) {
    // ZF == 1 Or SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjle");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjl");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setne(GuestInst *Inst) {
    // ZF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjne");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setno(GuestInst *Inst) {
    // OF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjno");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setnp(GuestInst *Inst) {
    // PF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjnp");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjns");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seto(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjo");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setp(GuestInst *Inst) {
    // PF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjp");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sets(GuestInst *Inst) {
    // SF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjs");
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

