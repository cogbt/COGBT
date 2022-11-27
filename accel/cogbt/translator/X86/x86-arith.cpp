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
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, CF_BIT));
    if (Src0->getType()->getIntegerBitWidth() < 64) {
        CF = Builder.CreateTrunc(CF, Src0->getType());
    }
    Value *Dest = Builder.CreateAdd(Builder.CreateAdd(Src0, Src1), CF);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    // FIXME! EFLAG calculate should be fixed.
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
    CalcEflag(Inst, Dest, High, Low);
}

void X86Translator::translate_imul(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int OpndNum = InstHdl.getOpndNum();
    if (OpndNum == 1) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        Value *Src1 = LoadGMRValue(Src0->getType(), X86Config::RAX);
        Value *Dest = nullptr, *High = nullptr, *Low = nullptr;
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
        CalcEflag(Inst, Dest, High, nullptr);
    } else if (OpndNum == 2) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
        Value *Dest = nullptr, *TruncDest = nullptr;
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
        CalcEflag(Inst, Dest, TruncDest, nullptr);
    } else {
        dbgs() << "Untranslated instruction imul imm\n";
        exit(-1);
    }
}

void X86Translator::translate_mulpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulpd\n";
    exit(-1);
}
void X86Translator::translate_mulps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulps\n";
    exit(-1);
}
void X86Translator::translate_mulsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulsd\n";
    exit(-1);
}
void X86Translator::translate_mulss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulss\n";
    exit(-1);
}
void X86Translator::translate_mulx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulx\n";
    exit(-1);
}
void X86Translator::translate_fmul(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fmul\n";
    exit(-1);
}
void X86Translator::translate_fimul(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fimul\n";
    exit(-1);
}
void X86Translator::translate_fmulp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fmulp\n";
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
#if (LLVM_VERSION_MAJOR > 8)
        FunctionCallee F = Mod->getOrInsertFunction("helper_divb_AL", FuncTy);
        Builder.CreateCall(FuncTy, F.getCallee(), {CPUEnv, Divisor});
#else
        Value *Func = Mod->getOrInsertFunction("helper_divb_AL", FuncTy);
        Builder.CreateCall(Func, {CPUEnv, Divisor});
#endif
        ReloadGMRValue(X86Config::RAX);
        break;
    }
    case 16: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
#if (LLVM_VERSION_MAJOR > 8)
        FunctionCallee F = Mod->getOrInsertFunction("helper_divw_AX", FuncTy);
        Builder.CreateCall(FuncTy, F.getCallee(), {CPUEnv, Divisor});
#else
        Value *Func = Mod->getOrInsertFunction("helper_divw_AX", FuncTy);
        Builder.CreateCall(Func, {CPUEnv, Divisor});
#endif
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 32: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
#if (LLVM_VERSION_MAJOR > 8)
        FunctionCallee F = Mod->getOrInsertFunction("helper_divl_EAX", FuncTy);
        Builder.CreateCall(FuncTy, F.getCallee(), {CPUEnv, Divisor});
#else
        Value *Func = Mod->getOrInsertFunction("helper_divl_EAX", FuncTy);
        Builder.CreateCall(Func, {CPUEnv, Divisor});
#endif
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    case 64: {
        Divisor = Builder.CreateZExt(Divisor, Int64Ty);
        FlushGMRValue(X86Config::RAX);
        FlushGMRValue(X86Config::RDX);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy,Int64Ty}, false);
#if (LLVM_VERSION_MAJOR > 8)
        FunctionCallee F = Mod->getOrInsertFunction("helper_divq_EAX", FuncTy);
        Builder.CreateCall(FuncTy, F.getCallee(), {CPUEnv, Divisor});
#else
        Value *Func = Mod->getOrInsertFunction("helper_divq_EAX", FuncTy);
        Builder.CreateCall(Func, {CPUEnv, Divisor});
#endif
        ReloadGMRValue(X86Config::RAX);
        ReloadGMRValue(X86Config::RDX);
        break;
    }
    default:
        llvm_unreachable("Unexpected bit width of div\n");
    }
    /* Value *Dividend = nullptr, *Quotient = nullptr, *Remainder = nullptr; */
    /* switch (Divisor->getType()->getIntegerBitWidth()) { */
    /* case 8: */
    /*     Dividend = LoadGMRValue(Int16Ty, X86Config::RAX); */
    /*     Divisor = Builder.CreateZExt(Divisor, Int16Ty); */
    /*     Quotient = Builder.CreateUDiv(Dividend, Divisor); */
    /*     Remainder = Builder.CreateURem(Dividend, Divisor); */
    /*     // Store Quotient and Remainder into AL/AH. */
    /*     Remainder = Builder.CreateShl(Remainder, ConstInt(Int16Ty, 8)); */
    /*     Remainder = Builder.CreateZExt(Remainder, ) */
    /*     Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX); */
    /*     RAX = Builder.CreateAnd(RAX, ConstInt(Int64Ty, 0xffffffffffff0000)); */
    /*     RAX = Builder.CreateOr(RAX, Remainder); */

    /*     break; */
    /* case 16: */

    /*     break; */
    /* case 32: */
    /*     break; */
    /* case 64: */
    /*     break; */
    /* default: */
    /*     llvm_unreachable("Unexpected bit width of div\n"); */
    /* } */
}

void X86Translator::translate_divpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divpd\n";
    exit(-1);
}
void X86Translator::translate_divps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divps\n";
    exit(-1);
}
void X86Translator::translate_fdivr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdivr\n";
    exit(-1);
}
void X86Translator::translate_fidivr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fidivr\n";
    exit(-1);
}
void X86Translator::translate_fdivrp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdivrp\n";
    exit(-1);
}
void X86Translator::translate_divsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divsd\n";
    exit(-1);
}
void X86Translator::translate_divss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction divss\n";
    exit(-1);
}
void X86Translator::translate_fdiv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdiv\n";
    exit(-1);
}
void X86Translator::translate_fidiv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fidiv\n";
    exit(-1);
}
void X86Translator::translate_fdivp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdivp\n";
    exit(-1);
}
