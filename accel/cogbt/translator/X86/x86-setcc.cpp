#include "x86-translator.h"

void X86Translator::translate_setae(GuestInst *Inst) {
    // Set if CF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjae", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seta(GuestInst *Inst) {
    // Set if CF == 0 AND ZF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setja", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setbe(GuestInst *Inst) {
    // Set if CF == 1 OR ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjbe", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setb(GuestInst *Inst) {
    // Set if CF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjb", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sete(GuestInst *Inst) {
    // Set if ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setje", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setge(GuestInst *Inst) {
    // Set if SF == OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjge", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setg(GuestInst *Inst) {
    // ZF == 0 and SF == OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjg", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setle(GuestInst *Inst) {
    // ZF == 1 Or SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjle", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjl", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setne(GuestInst *Inst) {
    // ZF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjne", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setno(GuestInst *Inst) {
    // OF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjno", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setnp(GuestInst *Inst) {
    // PF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjnp", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjns", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_seto(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjo", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_setp(GuestInst *Inst) {
    // PF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjp", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

void X86Translator::translate_sets(GuestInst *Inst) {
    // SF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjs", FTy);
    Value *Val = Builder.CreateCall(FTy, Func);
    Val = Builder.CreateZExtOrTrunc(Val, GetOpndLLVMType(InstHdl.getOpnd(0)));
    StoreOperand(Val, InstHdl.getOpnd(0));
}

