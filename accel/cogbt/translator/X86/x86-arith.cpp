#include "x86-translator.h"

void X86Translator::translate_aaa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aaa\n";
    exit(-1);
}
void X86Translator::translate_aad(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aad\n";
    exit(-1);
}
void X86Translator::translate_aam(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aam\n";
    exit(-1);
}
void X86Translator::translate_aas(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aas\n";
    exit(-1);
}

void X86Translator::translate_adc(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));

    // Load CF
    Value *CF = GetLBTFlag(0x1);
    if (Src0->getType()->getIntegerBitWidth() < 64) {
        CF = Builder.CreateTrunc(CF, Src0->getType());
    }
    Value *Dest = Builder.CreateAdd(Builder.CreateAdd(Src0, Src1), CF);

    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_adcx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction adcx\n";
    exit(-1);
}

void X86Translator::translate_add(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateAdd(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_sub(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateSub(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_sbb(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *CF = GetLBTFlag(0x1);
    if (Src0->getType()->getIntegerBitWidth() != 64) {
        CF = Builder.CreateTrunc(CF, Src0->getType());
    }
    Src0 = Builder.CreateAdd(Src0, CF);
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateSub(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_cmp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateSub(Src1, Src0);
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_mul(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadGMRValue(Src0->getType(), X86Config::RAX);
    Value *Dest = nullptr, *High = nullptr, *Low = nullptr;
    Value *FlagSrc0 = Src0, *FlagSrc1 = Src1;
    switch (Src0->getType()->getIntegerBitWidth()) {
    case 8: {
        Src0 = Builder.CreateZExt(Src0, Int16Ty);
        Src1 = Builder.CreateZExt(Src1, Int16Ty);
        Dest = Builder.CreateMul(Src0, Src1);
        // store Dest into low 16bit of RAX
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        RAX = Builder.CreateAnd(RAX, ConstInt(Int64Ty, 0xffffffffffff0000));
        Value *Res = Builder.CreateZExt(Dest, Int64Ty);
        RAX = Builder.CreateOr(RAX, Res);
        StoreGMRValue(RAX, X86Config::RAX);
        break;
    }
    case 16: {
        Src0 = Builder.CreateZExt(Src0, Int32Ty);
        Src1 = Builder.CreateZExt(Src1, Int32Ty);
        Dest = Builder.CreateMul(Src0, Src1);
        // Store Dest into DX:AX
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        RAX = Builder.CreateAnd(RAX, ConstInt(Int64Ty, 0xffffffffffff0000));
        Low = Builder.CreateTrunc(Dest, Int16Ty);
        Low = Builder.CreateZExt(Low, Int64Ty);
        RAX = Builder.CreateOr(RAX, Low);
        StoreGMRValue(RAX, X86Config::RAX);

        Value *RDX = LoadGMRValue(Int64Ty, X86Config::RDX);
        RDX = Builder.CreateAnd(RDX, ConstInt(Int64Ty, 0xffffffffffff0000));
        High = Builder.CreateLShr(Dest, ConstInt(Int32Ty, 16));
        High = Builder.CreateTrunc(High, Int16Ty);
        High = Builder.CreateZExt(High, Int64Ty);
        RDX = Builder.CreateOr(RDX, High);
        StoreGMRValue(RDX, X86Config::RDX);
        break;
    }
    case 32: {
        Src0 = Builder.CreateZExt(Src0, Int64Ty);
        Src1 = Builder.CreateZExt(Src1, Int64Ty);
        Dest = Builder.CreateMul(Src0, Src1);
        // Store Dest into EDX:EAX
        Low = Builder.CreateTrunc(Dest, Int32Ty);
        Low = Builder.CreateZExt(Low, Int64Ty);
        StoreGMRValue(Low, X86Config::RAX);

        High = Builder.CreateLShr(Dest, ConstInt(Int64Ty, 32));
        High = Builder.CreateTrunc(High, Int32Ty);
        High = Builder.CreateZExt(High, Int64Ty);
        StoreGMRValue(High, X86Config::RDX);
        break;
    }
    case 64: {
        Src0 = Builder.CreateZExt(Src0, Int128Ty);
        Src1 = Builder.CreateZExt(Src1, Int128Ty);
        Dest = Builder.CreateMul(Src0, Src1);
        // Store Dest into RDX:RAX
        Low = Builder.CreateTrunc(Dest, Int64Ty);
        StoreGMRValue(Low, X86Config::RAX);

        High = Builder.CreateLShr(Dest, ConstInt(Int128Ty, 64));
        High = Builder.CreateTrunc(High, Int64Ty);
        StoreGMRValue(High, X86Config::RDX);
        break;
    }
    default:
        llvm_unreachable("mul unknown src opnd size\n");
    }
    CalcEflag(Inst, Dest, FlagSrc0, FlagSrc1);
}

void X86Translator::translate_imul(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int OpndNum = InstHdl.getOpndNum();
    if (OpndNum == 1) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        Value *Src1 = LoadGMRValue(Src0->getType(), X86Config::RAX);
        Value *Dest = nullptr, *High = nullptr, *Low = nullptr;
        Value *FlagSrc0 = Src0, *FlagSrc1 = Src1;
        switch (Src0->getType()->getIntegerBitWidth()) {
        case 8: {
            Src0 = Builder.CreateSExt(Src0, Int16Ty);
            Src1 = Builder.CreateSExt(Src1, Int16Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            // store Dest into low 16bit of RAX
            Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
            RAX = Builder.CreateAnd(RAX, ConstInt(Int64Ty, 0xffffffffffff0000));
            Value *Res = Builder.CreateZExt(Dest, Int64Ty);
            RAX = Builder.CreateOr(RAX, Res);
            StoreGMRValue(RAX, X86Config::RAX);
            break;
        }
        case 16: {
            Src0 = Builder.CreateSExt(Src0, Int32Ty);
            Src1 = Builder.CreateSExt(Src1, Int32Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            // Store Dest into DX:AX
            Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
            RAX = Builder.CreateAnd(RAX, ConstInt(Int64Ty, 0xffffffffffff0000));
            Low = Builder.CreateTrunc(Dest, Int16Ty);
            Low = Builder.CreateZExt(Low, Int64Ty);
            RAX = Builder.CreateOr(RAX, Low);
            StoreGMRValue(RAX, X86Config::RAX);

            Value *RDX = LoadGMRValue(Int64Ty, X86Config::RDX);
            RDX = Builder.CreateAnd(RDX, ConstInt(Int64Ty, 0xffffffffffff0000));
            High = Builder.CreateLShr(Dest, ConstInt(Int32Ty, 16));
            High = Builder.CreateTrunc(High, Int16Ty);
            High = Builder.CreateZExt(High, Int64Ty);
            RDX = Builder.CreateOr(RDX, High);
            StoreGMRValue(RDX, X86Config::RDX);
            break;
        }
        case 32: {
            Src0 = Builder.CreateSExt(Src0, Int64Ty);
            Src1 = Builder.CreateSExt(Src1, Int64Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            // Store Dest into EDX:EAX
            Low = Builder.CreateTrunc(Dest, Int32Ty);
            Low = Builder.CreateZExt(Low, Int64Ty);
            StoreGMRValue(Low, X86Config::RAX);

            High = Builder.CreateLShr(Dest, ConstInt(Int64Ty, 32));
            High = Builder.CreateTrunc(High, Int32Ty);
            High = Builder.CreateZExt(High, Int64Ty);
            StoreGMRValue(High, X86Config::RDX);
            break;
        }
        case 64: {
            Src0 = Builder.CreateSExt(Src0, Int128Ty);
            Src1 = Builder.CreateSExt(Src1, Int128Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            // Store Dest into RDX:RAX
            Low = Builder.CreateTrunc(Dest, Int64Ty);
            StoreGMRValue(Low, X86Config::RAX);

            High = Builder.CreateLShr(Dest, ConstInt(Int128Ty, 64));
            High = Builder.CreateTrunc(High, Int64Ty);
            StoreGMRValue(High, X86Config::RDX);
            break;
        }
        default:
            llvm_unreachable("mul unknown src opnd size\n");
        }
        CalcEflag(Inst, Dest, FlagSrc0, FlagSrc1);
    } else if (OpndNum == 2) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
        Value *Dest = nullptr, *TruncDest = nullptr;
        Value *FlagSrc0 = Src0, *FlagSrc1 = Src1;
        int BitWidth = Src0->getType()->getIntegerBitWidth();
        if (BitWidth == 16) {
            Src0 = Builder.CreateSExt(Src0, Int32Ty);
            Src1 = Builder.CreateSExt(Src1, Int32Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            TruncDest = Builder.CreateTrunc(Dest, Int16Ty);
            StoreOperand(TruncDest, InstHdl.getOpnd(1));
        } else if (BitWidth == 32) {
            Src0 = Builder.CreateSExt(Src0, Int64Ty);
            Src1 = Builder.CreateSExt(Src1, Int64Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            TruncDest = Builder.CreateTrunc(Dest, Int32Ty);
            StoreOperand(TruncDest, InstHdl.getOpnd(1));
        } else {
            assert(BitWidth == 64);
            Src0 = Builder.CreateSExt(Src0, Int128Ty);
            Src1 = Builder.CreateSExt(Src1, Int128Ty);
            Dest = Builder.CreateMul(Src0, Src1);
            TruncDest = Builder.CreateTrunc(Dest, Int64Ty);
            StoreOperand(TruncDest, InstHdl.getOpnd(1));
        }
        CalcEflag(Inst, Dest, FlagSrc0, FlagSrc1);
    } else {
        Type *Ty = GetOpndLLVMType(InstHdl.getOpnd(1));
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0), Ty);
        Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
        Value *Dest = Builder.CreateMul(Src0, Src1);
        StoreOperand(Dest, InstHdl.getOpnd(2));
        CalcEflag(Inst, Dest, Src0, Src1);
    }
}

void X86Translator::translate_daa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction daa\n";
    exit(-1);
}
void X86Translator::translate_das(GuestInst *Inst) {
    dbgs() << "Untranslated instruction das\n";
    exit(-1);
}
void X86Translator::translate_xadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xadd\n";
    exit(-1);
}
void X86Translator::translate_mulpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulpd\n";
    exit(-1);
}
void X86Translator::translate_mulps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulps\n";
    exit(-1);
}

void X86Translator::translate_div(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Divisor = LoadOperand(InstHdl.getOpnd(0));
    FunctionType *FuncTy = nullptr;
    switch (Divisor->getType()->getIntegerBitWidth()) {
    case 8: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_divb_AL", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        break;
    }
    case 16: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_divw_AX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 32: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_divl_EAX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 64: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_divq_EAX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    default:
        llvm_unreachable("Unexpected bit width of div\n");
    }
}

void X86Translator::translate_idiv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Divisor = LoadOperand(InstHdl.getOpnd(0));
    FunctionType *FuncTy = nullptr;
    switch (Divisor->getType()->getIntegerBitWidth()) {
    case 8: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_idivb_AL", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        break;
    }
    case 16: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_idivw_AX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 32: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_idivl_EAX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 64: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
        CallFunc(FuncTy, "helper_idivq_EAX", {CPUEnv, Divisor});
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    default:
        llvm_unreachable("Unexpected bit width of div\n");
    }
}

void X86Translator::translate_divpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divpd\n";
    exit(-1);
}
void X86Translator::translate_divps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divps\n";
    exit(-1);
}

void X86Translator::translate_dec(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateSub(Src, ConstInt(Src->getType(), 1));
    StoreOperand(Dest, InstHdl.getOpnd(0));
    CalcEflag(Inst, Dest, Src, nullptr);
}

void X86Translator::translate_inc(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateAdd(Src, ConstInt(Src->getType(), 1));
    StoreOperand(Dest, InstHdl.getOpnd(0));
    CalcEflag(Inst, Dest, Src, nullptr);
}

void X86Translator::translate_divsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divsd\n";
    exit(-1);
}
void X86Translator::translate_divss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divss\n";
    exit(-1);
}

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
        Value *Src0 = Builder.CreateLoad(RSI);
        Value *Src1 = Builder.CreateLoad(RDI);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateIntToPtr(RSI, Int8PtrTy);
        Value *Src1 = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Src0 = Builder.CreateLoad(Src0);
        Src1 = Builder.CreateLoad(Src1);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateLoad(RSI);
        Value *Src1 = Builder.CreateLoad(RDI);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateIntToPtr(RSI, Int16PtrTy);
        Value *Src1 = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Src0 = Builder.CreateLoad(Src0);
        Src1 = Builder.CreateLoad(Src1);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateLoad(RSI);
        Value *Src1 = Builder.CreateLoad(RDI);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateIntToPtr(RSI, Int32PtrTy);
        Value *Src1 = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Src0 = Builder.CreateLoad(Src0);
        Src1 = Builder.CreateLoad(Src1);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateLoad(RSI);
        Value *Src1 = Builder.CreateLoad(RDI);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
        Value *Src0 = Builder.CreateIntToPtr(RSI, Int64PtrTy);
        Value *Src1 = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Src0 = Builder.CreateLoad(Src0);
        Src1 = Builder.CreateLoad(Src1);
        Value *Res = Builder.CreateSub(Src0, Src1);
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
