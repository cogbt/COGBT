#include "x86-translator.h"

void X86Translator::translate_xor(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateXor(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_and(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateAnd(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_or(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateOr(Src0, Src1);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_sar(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }
    Value *Dest = Builder.CreateAShr(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }
    Value *Dest = Builder.CreateLShr(Src1, Src0);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shl(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int OpndNum = InstHdl.getOpndNum();
    assert(OpndNum == 1 || OpndNum == 2);

    Value *Src0 = nullptr;  // shift opnd
    Value *Src1 = nullptr;  // src/dest opnd
    if (OpndNum == 2) {
        Src0 = LoadOperand(InstHdl.getOpnd(0));
        Src1 = LoadOperand(InstHdl.getOpnd(1));
    } else {
        Src0 = LoadGMRValue(Int8Ty, X86Config::ECX);
        Src1 = LoadOperand(InstHdl.getOpnd(0));
    }
    int Src0Size = Src0->getType()->getIntegerBitWidth();
    int Src1Size = Src1->getType()->getIntegerBitWidth();
    if (Src0Size < Src1Size) {
        Src0 = Builder.CreateZExt(Src0, Src1->getType());
    }

    Value *Dest = Builder.CreateShl(Src1, Src0);
    /* StoreOperand(Dest, InstHdl.getOpnd(1)); */
    if (OpndNum == 2)
        StoreOperand(Dest, InstHdl.getOpnd(1));
    else
        StoreOperand(Dest, InstHdl.getOpnd(0));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_shld(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));
    X86OperandHandler Opnd2(InstHdl.getOpnd(2));
    BasicBlock *ShiftBB =
        BasicBlock::Create(Context, "ShldBB", TransFunc, ExitBB);
    BasicBlock *NShiftBB =
        BasicBlock::Create(Context, "NoShiftBB", TransFunc, ExitBB);

    Value *Shift = nullptr;
    Value *Src = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = LoadOperand(InstHdl.getOpnd(2));
    Type *OpndTy = Dest->getType();

    int modsize = OpndTy->getIntegerBitWidth() == 64 ? 64 : 32;
    // Determine Shift value.
    if (Opnd0.isImm()) {
        if (Opnd0.getIMM() == 0)
            return;
        Shift = ConstInt(OpndTy, Opnd0.getIMM() % modsize);
    } else {
        Shift = LoadOperand(InstHdl.getOpnd(0));
        Shift = Builder.CreateZExtOrTrunc(Shift, OpndTy);
        Shift = Builder.CreateAnd(Shift, ConstInt(OpndTy, modsize - 1));
    }
    Value *ShouldShift = Builder.CreateICmpNE(Shift, ConstInt(OpndTy, 0));
    SyncAllGMRValue();
    Builder.CreateCondBr(ShouldShift, ShiftBB, NShiftBB);

    Builder.SetInsertPoint(ShiftBB);
    // Calculate the final dest value.
    Value *Result =
        Builder.CreateIntrinsic(Intrinsic::fshl, OpndTy, {Dest, Src, Shift});
    StoreOperand(Result, InstHdl.getOpnd(2));

    // Calculate eflags.
    CalcEflag(Inst, Result, nullptr, nullptr);
    int opndbits = OpndTy->getIntegerBitWidth();
    // 1. Get SF,ZF,PF
    Value *Flag = GetLBTFlag(0x1a);
    // 2. Calculate CF (the last bit shift out dest)
    Value *ShiftCF = Builder.CreateAdd(Shift, ConstInt(OpndTy, -1));
    Value *CF = Builder.CreateShl(Dest, ShiftCF);
    CF = Builder.CreateLShr(CF, ConstInt(OpndTy, opndbits - 1));
    CF = Builder.CreateZExtOrTrunc(CF, Int64Ty);
    // 3. Calculate OF (for 1 bit shift and sign chang)
    Value *HighBit0 = Builder.CreateLShr(Dest, ConstInt(OpndTy, opndbits - 1));
    Value *HighBit1 = Builder.CreateLShr(Dest, ConstInt(OpndTy, opndbits - 2));
    Value *OF = Builder.CreateXor(HighBit0, HighBit1);
    OF = Builder.CreateAnd(OF, ConstInt(OpndTy, 1));
    OF = Builder.CreateShl(OF, ConstInt(OpndTy, OF_SHIFT));
    // 4. Update eflag
    Flag = Builder.CreateOr(Flag, CF);
    Flag = Builder.CreateOr(Flag, OF);
    SetLBTFlag(Flag);
    SyncAllGMRValue();
    Builder.CreateBr(NShiftBB);

    Builder.SetInsertPoint(NShiftBB);
}

void X86Translator::translate_shrd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));
    X86OperandHandler Opnd2(InstHdl.getOpnd(2));
    BasicBlock *ShiftBB =
        BasicBlock::Create(Context, "ShrdBB", TransFunc, ExitBB);
    BasicBlock *NShiftBB =
        BasicBlock::Create(Context, "NoShiftBB", TransFunc, ExitBB);

    Value *Shift = nullptr;
    Value *Src = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = LoadOperand(InstHdl.getOpnd(2));
    Type *OpndTy = Dest->getType();

    int modsize = OpndTy->getIntegerBitWidth() == 64 ? 64 : 32;
    // Determine Shift value.
    if (Opnd0.isImm()) {
        if (Opnd0.getIMM() == 0)
            return;
        Shift = ConstInt(OpndTy, Opnd0.getIMM() % modsize);
    } else {
        Shift = LoadOperand(InstHdl.getOpnd(0));
        Shift = Builder.CreateZExtOrTrunc(Shift, OpndTy);
        Shift = Builder.CreateAnd(Shift, ConstInt(OpndTy, modsize - 1));
    }
    Value *ShouldShift = Builder.CreateICmpNE(Shift, ConstInt(OpndTy, 0));
    SyncAllGMRValue();
    Builder.CreateCondBr(ShouldShift, ShiftBB, NShiftBB);

    Builder.SetInsertPoint(ShiftBB);
    // Calculate the final dest value.
    Value *Result =
        Builder.CreateIntrinsic(Intrinsic::fshr, OpndTy, {Src, Dest, Shift});
    StoreOperand(Result, InstHdl.getOpnd(2));

    // Calculate eflags.
    int opndbits = OpndTy->getIntegerBitWidth();
    // 1. Get SF,ZF,PF
    CalcEflag(Inst, Result, nullptr, nullptr);
    Value *Flag = GetLBTFlag(0x1a);
    // 2. Calculate CF (the last bit shift out dest)
    Value *ShiftCF = Builder.CreateAdd(Shift, ConstInt(OpndTy, -1));
    Value *CF = Builder.CreateShl(Dest, ShiftCF);
    CF = Builder.CreateAnd(CF, ConstInt(OpndTy, 1));
    CF = Builder.CreateZExtOrTrunc(CF, Int64Ty);
    // 3. Calculate OF (for 1 bit shift and sign chang)
    Value *DestHBit = Builder.CreateLShr(Dest, ConstInt(OpndTy, opndbits - 1));
    Value *OF = Builder.CreateXor(DestHBit, Src);
    OF = Builder.CreateAnd(OF, ConstInt(OpndTy, 1));
    OF = Builder.CreateShl(OF, ConstInt(OpndTy, OF_SHIFT));
    // 4. Update eflag
    Flag = Builder.CreateOr(Flag, CF);
    Flag = Builder.CreateOr(Flag, OF);
    SetLBTFlag(Flag);
    SyncAllGMRValue();
    Builder.CreateBr(NShiftBB);

    Builder.SetInsertPoint(NShiftBB);
}

void X86Translator::translate_shlx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shlx\n";
    exit(-1);
}

void X86Translator::translate_shrx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shrx\n";
    exit(-1);
}

void X86Translator::translate_neg(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateNeg(Src);
    StoreOperand(Dest, InstHdl.getOpnd(0));
    CalcEflag(Inst, Dest, Src, ConstInt(Src->getType(), 0));
}

void X86Translator::translate_nop(GuestInst *Inst) {}

void X86Translator::translate_not(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateNot(Src);
    StoreOperand(Dest, InstHdl.getOpnd(0));
}

void X86Translator::translate_bsf(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = LoadOperand(InstHdl.getOpnd(1));
    Value *isZero = Builder.CreateICmpEQ(Src, ConstInt(Src->getType(), 0));
    Value *Src64 = Src;
    if (Src->getType()->getIntegerBitWidth() != 64)
        Src64 = Builder.CreateZExt(Src, Int64Ty);
    FunctionType *FuncTy = FunctionType::get(Int64Ty, {Int64Ty,Int1Ty}, false);
    Value *Idx = CallFunc(FuncTy, "llvm.cttz.i64", {Src64, ConstInt(Int1Ty, 0)});
    if (Src->getType()->getIntegerBitWidth() != 64)
        Idx = Builder.CreateTrunc(Idx, Src->getType());

    Dest = Builder.CreateSelect(isZero, Dest, Idx);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    /* CalcEflag(Inst, Src, nullptr, nullptr); */
    Value *ZF = Builder.CreateSelect(isZero, ConstInt(Int64Ty, -1),
                                     ConstInt(Int64Ty, 0));
    SetLBTFlag(ZF, 0x8);
}

void X86Translator::translate_bsr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = LoadOperand(InstHdl.getOpnd(1));
    Value *isZero = Builder.CreateICmpEQ(Src, ConstInt(Src->getType(), 0));
    Value *Src64 = Src;
    if (Src->getType()->getIntegerBitWidth() != 64)
        Src64 = Builder.CreateZExt(Src, Int64Ty);
    FunctionType *FuncTy = FunctionType::get(Int64Ty, {Int64Ty,Int1Ty}, false);
    Value *Idx = CallFunc(FuncTy, "llvm.ctlz.i64", {Src64, ConstInt(Int1Ty, 0)});
    if (Src->getType()->getIntegerBitWidth() != 64) {
        Idx = Builder.CreateTrunc(Idx, Src->getType());
    }
    Idx = Builder.CreateSub(ConstInt(Idx->getType(), 63), Idx);

    Dest = Builder.CreateSelect(isZero, Dest, Idx);
    StoreOperand(Dest, InstHdl.getOpnd(1));
    /* CalcEflag(Inst, Src, nullptr, nullptr); */
    Value *ZF = Builder.CreateSelect(isZero, ConstInt(Int64Ty, -1),
                                     ConstInt(Int64Ty, 0));
    SetLBTFlag(ZF, 0x8);
}

void X86Translator::translate_bswap(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateIntrinsic(Intrinsic::bswap, Src->getType(), Src);
    StoreOperand(Dest, InstHdl.getOpnd(0));
}

void X86Translator::translate_rol(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Type *Ty = Src1->getType();
    Src0 = Builder.CreateZExtOrTrunc(Src0, Ty);

    FunctionType *FuncTy = FunctionType::get(Ty, {Ty, Ty, Ty}, false);
    std::string IntrinsicName("");
    if (Ty->getIntegerBitWidth() == 8) {
        IntrinsicName = "llvm.fshl.i8";
    } else if (Ty->getIntegerBitWidth() == 16) {
        IntrinsicName = "llvm.fshl.i16";
    } else if (Ty->getIntegerBitWidth() == 32) {
        IntrinsicName = "llvm.fshl.i32";
    } else {
        IntrinsicName = "llvm.fshl.i64";
    }
    Value *Dest = CallFunc(FuncTy, IntrinsicName, {Src1, Src1, Src0});
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_ror(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Type *Ty = Src1->getType();
    Src0 = Builder.CreateZExtOrTrunc(Src0, Ty);

    FunctionType *FuncTy = FunctionType::get(Ty, {Ty, Ty, Ty}, false);
    std::string IntrinsicName("");
    if (Ty->getIntegerBitWidth() == 8) {
        IntrinsicName = "llvm.fshr.i8";
    } else if (Ty->getIntegerBitWidth() == 16) {
        IntrinsicName = "llvm.fshr.i16";
    } else if (Ty->getIntegerBitWidth() == 32) {
        IntrinsicName = "llvm.fshr.i32";
    } else {
        IntrinsicName = "llvm.fshr.i64";
    }
    Value *Dest = CallFunc(FuncTy, IntrinsicName, {Src1, Src1, Src0});
    StoreOperand(Dest, InstHdl.getOpnd(1));
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_rorx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rorx\n";
    exit(-1);
}

void X86Translator::translate_test(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Dest = Builder.CreateAnd(Src0, Src1);
    CalcEflag(Inst, Dest, Src0, Src1);
}

void X86Translator::translate_tzcnt(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *SrcIsZ = Builder.CreateICmpEQ(Src, ConstInt(Src->getType(), 0));
    Value *Dest = Builder.CreateIntrinsic(
        Intrinsic::cttz, {Src->getType(), Int1Ty}, {Src, ConstInt(Int1Ty, 0)});
    Value *DestIsZ = Builder.CreateICmpEQ(Dest, ConstInt(Dest->getType(), 0));
    StoreOperand(Dest, InstHdl.getOpnd(1));
    /* CalcEflag(Inst, Src, nullptr, nullptr); */
    Value *ZF = Builder.CreateSelect(DestIsZ, ConstInt(Int64Ty, ZF_BIT),
                                     ConstInt(Int64Ty, 0));
    Value *CF = Builder.CreateSelect(SrcIsZ, ConstInt(Int64Ty, CF_BIT),
                                     ConstInt(Int64Ty, 0));
    Value *Flag = Builder.CreateOr(ZF, CF);
    SetLBTFlag(Flag, 0x9);
}
