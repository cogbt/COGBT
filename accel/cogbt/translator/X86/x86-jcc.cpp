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
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), CF_BIT));
    CFVal = Builder.CreateICmpEQ(CFVal, ConstInt(CFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
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
        ConstInt(Flag->getType(), CF_BIT | ZF_BIT));
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
        ConstInt(Flag->getType(), CF_BIT | ZF_BIT));
    Cond = Builder.CreateICmpNE(Cond, ConstInt(Cond->getType(), 0));
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
    // CF == 1
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CFVal = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), CF_BIT));
    CFVal = Builder.CreateICmpNE(CFVal, ConstInt(CFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
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

void X86Translator::translate_jcxz(GuestInst *Inst) {
    // CX == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *CX = LoadGMRValue(Int16Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(CX, ConstInt(CX->getType(), 0));

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

void X86Translator::translate_jecxz(GuestInst *Inst) {
    // ECX == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *ECX = LoadGMRValue(Int32Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(ECX, ConstInt(ECX->getType(), 0));

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

void X86Translator::translate_je(GuestInst *Inst) {
    // ZF == 1
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
    // SF == OF
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT)); 
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT)); 
    Value *Same = Builder.CreateXor(SF, OF);
    Same = Builder.CreateAnd(Same, ConstInt(Int64Ty, 1));
    Value *Cond = Builder.CreateICmpEQ(Same, ConstInt(Same->getType(), 0));
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

void X86Translator::translate_jg(GuestInst *Inst) {
    // ZF == 0 AND SF == OF
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), ZF_BIT));
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT)); 
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT)); 
    Value *Same = Builder.CreateXor(SF, OF);
    Same = Builder.CreateAnd(Same, ConstInt(Int64Ty, 1));
    Value *Cond1 = Builder.CreateICmpEQ(ZF, ConstInt(ZF->getType(), 0));
    Value *Cond2 = Builder.CreateICmpEQ(Same, ConstInt(Same->getType(), 0));
    Value *Cond = Builder.CreateAnd(Cond1, Cond2);
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

void X86Translator::translate_jle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), ZF_BIT));
    Value *SFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), SF_BIT));
    Value *OFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), OF_BIT));
    Value *Cond1 = Builder.CreateICmpNE(ZFVal, ConstInt(Flag->getType(), 0));
    Value *Cond2 = Builder.CreateICmpNE(SFVal, OFVal);
    Value *Cond = Builder.CreateOr(Cond1, Cond2);
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

void X86Translator::translate_jl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), SF_SHIFT)); 
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Flag->getType(), OF_SHIFT)); 
    Value *Diff = Builder.CreateXor(SF, OF);
    Diff = Builder.CreateAnd(Diff, ConstInt(Int64Ty, 1));
    Value *Cond = Builder.CreateICmpEQ(Diff, ConstInt(Diff->getType(), 1));
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

void X86Translator::translate_jmp(GuestInst *Inst) {
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    X86InstHandler InstHdl(Inst);
    Value *Target = LoadOperand(InstHdl.getOpnd(0));
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(Target, EIPAddr);
    Builder.CreateBr(ExitBB);
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
    // OF == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *OFVal = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), OF_BIT));
    OFVal = Builder.CreateICmpEQ(OFVal, ConstInt(OFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(OFVal, TargetBB, FallThroughBB);

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

void X86Translator::translate_jnp(GuestInst *Inst) {
    // PF == 0
    dbgs() << "Untranslated instruction jnp\n";
    exit(-1);
    /* X86InstHandler InstHdl(Inst); */
    /* BasicBlock *TargetBB = */
    /*     BasicBlock::Create(Context, "target", TransFunc, ExitBB); */
    /* BasicBlock *FallThroughBB = */
    /*     BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB); */

    /* Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG); */
    /* Value *PFVal = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), PF_BIT)); */
    /* PFVal = Builder.CreateICmpEQ(PFVal, ConstInt(PFVal->getType(), 0)); */
    /* for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) { */
    /*     if (GMRVals[GMRId].isDirty()) { */
    /*         Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]); */
    /*         GMRVals[GMRId].setDirty(false); */
    /*     } */
    /* } */
    /* Builder.CreateCondBr(PFVal, TargetBB, FallThroughBB); */

    /* Builder.SetInsertPoint(FallThroughBB); */
    /* Value *EnvEIP = */
    /*     Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset())); */
    /* Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy); */
    /* Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr); */
    /* Builder.CreateBr(ExitBB); */

    /* Builder.SetInsertPoint(TargetBB); */
    /* EnvEIP = */
    /*     Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset())); */
    /* EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy); */
    /* Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr); */
    /* Builder.CreateBr(ExitBB); */
}

void X86Translator::translate_jns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SFVal = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), SF_BIT));
    SFVal = Builder.CreateICmpEQ(SFVal, ConstInt(SFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(SFVal, TargetBB, FallThroughBB);

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

void X86Translator::translate_jo(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *OFVal = Builder.CreateAnd(Flag, ConstInt(Flag->getType(), OF_BIT));
    OFVal = Builder.CreateICmpNE(OFVal, ConstInt(OFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(OFVal, TargetBB, FallThroughBB);

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

void X86Translator::translate_jp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jp\n";
    exit(-1);
}

void X86Translator::translate_jrcxz(GuestInst *Inst) {
    // RCX == 0
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(RCX, ConstInt(RCX->getType(), 0));

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

void X86Translator::translate_js(GuestInst *Inst) {
    // SF = 1
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);

    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), SF_BIT));
    SFVal = Builder.CreateICmpNE(SFVal, ConstInt(SFVal->getType(), 0));
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
            GMRVals[GMRId].setDirty(false);
        }
    }
    Builder.CreateCondBr(SFVal, TargetBB, FallThroughBB);

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
