#include "x86-translator.h"
#include "emulator.h"

void X86Translator::translate_jae(GuestInst *Inst) {
    // CF == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), InstHdl.getCFMask()));
    CFVal = Builder.CreateICmpEQ(CFVal, ConstInt(CFVal->getType(), 0));
    Builder.CreateCondBr(CFVal, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_ja(GuestInst *Inst) {
    // CF == 0 && ZF == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Cond = Builder.CreateAnd(
        Flag,
        ConstInt(Flag->getType(), InstHdl.getCFMask() | InstHdl.getZFMask()));
    Cond = Builder.CreateICmpEQ(Cond, ConstInt(Cond->getType(), 0));
    Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jbe(GuestInst *Inst) {
    // CF == 1 or ZF == 1
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *Cond = Builder.CreateAnd(
        Flag,
        ConstInt(Flag->getType(), InstHdl.getCFMask() | InstHdl.getZFMask()));
    Cond = Builder.CreateICmpEQ(Cond, ConstInt(Cond->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jb\n";
    exit(-1);
}
void X86Translator::translate_jcxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jcxz\n";
    exit(-1);
}
void X86Translator::translate_jecxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jecxz\n";
    exit(-1);
}
void X86Translator::translate_je(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), ZF_BIT));
    ZFVal = Builder.CreateICmpNE(ZFVal, ConstInt(ZFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(ZFVal, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jge(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jge\n";
    exit(-1);
}
void X86Translator::translate_jg(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jg\n";
    exit(-1);
}
void X86Translator::translate_jle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), InstHdl.getZFMask()));
    Value *SFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), InstHdl.getSFMask()));
    Value *OFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), InstHdl.getOFMask()));
    Value *Cond1 = Builder.CreateICmpNE(ZFVal, ConstInt(Flag->getType(), 0));
    Value *Cond2 = Builder.CreateICmpNE(SFVal, OFVal);
    Value *Cond = Builder.CreateOr(Cond1, Cond2);
    Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jl\n";
    exit(-1);
}
void X86Translator::translate_jmp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jmp\n";
    exit(-1);
}
void X86Translator::translate_jne(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), ZF_BIT));
    ZFVal = Builder.CreateICmpEQ(ZFVal, ConstInt(ZFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(ZFVal, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jno(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jno\n";
    exit(-1);
}
void X86Translator::translate_jnp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jnp\n";
    exit(-1);
}
void X86Translator::translate_jns(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jns\n";
    exit(-1);
}
void X86Translator::translate_jo(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jo\n";
    exit(-1);
}
void X86Translator::translate_jp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jp\n";
    exit(-1);
}
void X86Translator::translate_jrcxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jrcxz\n";
    exit(-1);
}
void X86Translator::translate_js(GuestInst *Inst) {
    dbgs() << "Untranslated instruction js\n";
    exit(-1);
}
