#include "x86-translator.h"

void X86Translator::translate_cmpsb(GuestInst *Inst) {
    // Cmp byte at DS:ESI with byte at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RSI = Builder.CreateIntToPtr(RSI, Int8PtrTy);
        RDI = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Value *Src1 = Builder.CreateLoad(Int64Ty, RSI);
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        RSI = Builder.CreateSub(RSI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check RCX and REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int8Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int8Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = Builder.CreateIntToPtr(RSI, Int8PtrTy);
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Src1 = Builder.CreateLoad(Int64Ty, Src1);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RSI = Builder.CreateSub(RSI, Step);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_cmpsw(GuestInst *Inst) {
    // Cmp word at DS:ESI with word at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RSI = Builder.CreateIntToPtr(RSI, Int16PtrTy);
        RDI = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Value *Src1 = Builder.CreateLoad(Int64Ty, RSI);
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
        RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        RSI = Builder.CreateSub(RSI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int16Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int16Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = Builder.CreateIntToPtr(RSI, Int16PtrTy);
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Src1 = Builder.CreateLoad(Int64Ty, Src1);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
        RSI = Builder.CreateSub(RSI, Step);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_cmpsd(GuestInst *Inst) {
    // Cmp double word at DS:ESI with double workd at address ES:EDI
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum()) {
        X86OperandHandler Opnd0(InstHdl.getOpnd(0));
        X86OperandHandler Opnd1(InstHdl.getOpnd(1));
        if (Opnd0.isXMM() || Opnd1.isXMM()) {
            llvm_unreachable("CMPSD mmx unfinished");
        }
    }
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RSI = Builder.CreateIntToPtr(RSI, Int32PtrTy);
        RDI = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Value *Src1 = Builder.CreateLoad(Int64Ty, RSI);
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        RSI = Builder.CreateSub(RSI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check RCX and REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int32Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int32Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = Builder.CreateIntToPtr(RSI, Int32PtrTy);
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Src1 = Builder.CreateLoad(Int64Ty, Src1);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RSI = Builder.CreateSub(RSI, Step);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_cmpsq(GuestInst *Inst) {
    // Cmp byte at DS:ESI with byte at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RSI = Builder.CreateIntToPtr(RSI, Int64PtrTy);
        RDI = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Value *Src1 = Builder.CreateLoad(Int64Ty, RSI);
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        RSI = Builder.CreateSub(RSI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        // 4. Check RCX and REPE REPNE exit condition
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int64Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int64Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = Builder.CreateIntToPtr(RSI, Int64PtrTy);
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Src1 = Builder.CreateLoad(Int64Ty, Src1);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RSI and RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RSI = Builder.CreateSub(RSI, Step);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RSI, X86Config::RSI);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_scasb(GuestInst *Inst) {
    // Cmp AL with byte at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at AL, address ES:RDI and calculate cmp result.
        Value *AL = LoadGMRValue(Int8Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Value *Src1 = AL;
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check RCX and REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int8Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int8Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at AL and ES:RDI
        Value *AL = LoadGMRValue(Int8Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = AL;
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_scasw(GuestInst *Inst) {
    // Cmp AX with word at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at AX, address ES:RDI and calculate cmp result.
        Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Value *Src1 = AX;
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int16Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int16Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = AX;
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_scasd(GuestInst *Inst) {
    // Cmp double word at EAX with double workd at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *EAX = LoadGMRValue(Int32Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Value *Src1 = EAX;
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        // 4. Check RCX and REPE REPNE exit condition
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int32Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int32Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *EAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = EAX;
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}

void X86Translator::translate_scasq(GuestInst *Inst) {
    // Cmp quadword at RAX with byte at address ES:EDI
    X86InstHandler InstHdl(Inst);
    BasicBlock *ECBB = nullptr, *EndBB = nullptr, *FlagBB = nullptr,
               *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        ECBB = BasicBlock::Create(Context, "EarlyCheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        FlagBB = BasicBlock::Create(Context, "FlagBB", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(ECBB);

        Builder.SetInsertPoint(ECBB);
        // Early check rcx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Load byte at address DS:RSI, ES:RDI and calculate cmp result.
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Value *Src1 = RAX;
        Value *Src0 = Builder.CreateLoad(Int64Ty, RDI);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        Value *ExitCond = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        // 4. Check RCX and REPE REPNE exit condition
        if (InstHdl.hasRepe()) {
            Value *ResIsNZ = Builder.CreateICmpNE(Res, ConstInt(Int64Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsNZ);
        } else if (InstHdl.hasRepne()) {
            Value *ResIsZ = Builder.CreateICmpEQ(Res, ConstInt(Int64Ty, 0));
            ExitCond = Builder.CreateOr(ExitCond, ResIsZ);
        }
        SyncAllGMRValue();
        Builder.CreateCondBr(ExitCond, FlagBB, LoopBodyBB);

        Builder.SetInsertPoint(FlagBB);
        // Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
        Builder.CreateBr(EndBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Load byte at address DS:ESI and ES:RDI
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        Value *Src1 = RAX;
        Value *Src0 = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Src0 = Builder.CreateLoad(Int64Ty, Src0);
        Value *Res = Builder.CreateSub(Src1, Src0);
        // 2. Update RDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Calculate Eflag
        CalcEflag(Inst, Res, Src0, Src1);
    }
}
