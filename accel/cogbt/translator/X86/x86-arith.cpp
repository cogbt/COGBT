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

