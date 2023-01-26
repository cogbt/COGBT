#include "x86-translator.h"
#include "emulator.h"

void X86Translator::GenJCCExit(GuestInst *Inst, Value *Cond) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    BindPhysicalReg();
    Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

    FunctionType *FTy = FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.cogbtexit", FTy);
    Value *Off = ConstInt(Int64Ty, GuestEIPOffset());

    // Create fallthrough link slot.
    Builder.SetInsertPoint(FallThroughBB);
    Value *NextPC = ConstInt(Int64Ty, InstHdl.getNextPC());
    Instruction *LinkSlot = Builder.CreateCall(FTy, Func, {NextPC, Off});
    AttachLinkInfoToIR(LinkSlot, LI_TBLINK, 0);
    // Jump back qemu.
    Builder.CreateCall(Mod->getFunction("epilogue"));
    Builder.CreateUnreachable();

    Builder.SetInsertPoint(TargetBB);
    Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());
    // Create target link slot
    LinkSlot = Builder.CreateCall(FTy, Func, {TargetPC, Off});
    AttachLinkInfoToIR(LinkSlot, LI_TBLINK, 1);
    // Jump back qemu.
    Builder.CreateCall(Mod->getFunction("epilogue"));
    Builder.CreateUnreachable();

    ExitBB->eraseFromParent();
}

void X86Translator::translate_jae(GuestInst *Inst) {
    // CF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjae", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_ja(GuestInst *Inst) {
    // CF == 0 && ZF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setja", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jbe(GuestInst *Inst) {
    // CF == 1 or ZF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjbe", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jb(GuestInst *Inst) {
    // CF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjb", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_je(GuestInst *Inst) {
    // ZF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setje", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jge(GuestInst *Inst) {
    // SF == OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjge", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jg(GuestInst *Inst) {
    // ZF == 0 AND SF == OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjg", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjle", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jl(GuestInst *Inst) {
    // SF != OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjl", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jmp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // Create link here, NOTE! Distinguish direct jmp or indirect jmp first.
    X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
    if (OpndHdl.isImm()) { // can be linked
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
        Value *Func = Mod->getOrInsertFunction("llvm.loongarch.cogbtexit", FTy);
        Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
        Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());

        Instruction *LinkSlot = Builder.CreateCall(FTy, Func, {TargetPC, Off});
        AttachLinkInfoToIR(LinkSlot, LI_TBLINK, 1);
    } else {
        Value *Target = LoadOperand(InstHdl.getOpnd(0));
        Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
        Value *EnvEIP = Builder.CreateGEP(Int8Ty, CPUEnv, Off);
        Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
        Builder.CreateStore(Target, EIPAddr);
    }
    SyncAllGMRValue();
    Builder.CreateBr(ExitBB);
}

void X86Translator::translate_jne(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjne", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jno(GuestInst *Inst) {
    // OF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjno", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jnp(GuestInst *Inst) {
    // PF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjnp", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jns(GuestInst *Inst) {
    // SF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjns", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jo(GuestInst *Inst) {
    // OF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjo", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jp(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjp", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_js(GuestInst *Inst) {
    // SF = 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjs", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jcxz(GuestInst *Inst) {
    // CX == 0
    Value *CX = LoadGMRValue(Int16Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(CX, ConstInt(CX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jecxz(GuestInst *Inst) {
    // ECX == 0
    Value *ECX = LoadGMRValue(Int32Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(ECX, ConstInt(ECX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jrcxz(GuestInst *Inst) {
    // RCX == 0
    Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(RCX, ConstInt(RCX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}
