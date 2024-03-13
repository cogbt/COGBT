#include "emulator.h"
#include "x86-translator.h"

// void X86Translator::SetQemuSTI(int i, Value *Val) {}

void X86Translator::X87FPR_Push() { CurrTBTop = (CurrTBTop - 1) & 7; }

void X86Translator::X87FPR_Pop() { CurrTBTop = (CurrTBTop + 1) & 7; }

X86Config::X86MappedRegsId X86Translator::X87GetCurrST0() {
    // assert(0 && "Not implemented X87GetCurrST0");
    return (X86Config::X86MappedRegsId)(X86Config::ST0 + CurrTBTop);
}

X86Config::X86MappedRegsId X86Translator::X87GetCurrSTI(int i) {
    // assert(0 && "Not implemented X87GetCurrSTI");
    int idx = (CurrTBTop + i) & 7;
    return (X86Config::X86MappedRegsId)(X86Config::ST0 + idx);
}

void X86Translator::FlushFPRValue(std::string FPR, Value *FV, bool isInt) {
    FunctionType *FuncTy = nullptr;
    if (FV->getType()->isFloatTy()) {
        assert(!isInt);
        FV = Builder.CreateBitCast(FV, Int32Ty);
    } else if (FV->getType()->isDoubleTy()) {
        assert(!isInt);
        FV = Builder.CreateBitCast(FV, Int64Ty);
    } else {
        assert(FV->getType()->isIntegerTy());
    }
    int FVBitWidth = FV->getType()->getIntegerBitWidth();
    if (FVBitWidth == 16) {
        FV = Builder.CreateSExt(FV, Int32Ty);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        assert(isInt && "Can't treat 16bit value as float\n");
        CallFunc(FuncTy, "helper_fildl_" + FPR, {CPUEnv, FV});
    } else if (FVBitWidth == 32) {
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        if (isInt)
            CallFunc(FuncTy, "helper_fildl_" + FPR, {CPUEnv, FV});
        else
            CallFunc(FuncTy, "helper_flds_" + FPR, {CPUEnv, FV});
    } else if (FVBitWidth == 64) {
        // dbgs() << "11\n";
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);
        if (isInt)
            CallFunc(FuncTy, "helper_fildll_" + FPR, {CPUEnv, FV});
        else
            CallFunc(FuncTy, "helper_fldl_" + FPR, {CPUEnv, FV});
    } else {
        llvm_unreachable("Unsupported FV bitwidth");
    }
}

Value *X86Translator::ReloadFPRValue(std::string FPR, int LoadSize,
                                     bool isInt) {
    Value *MemVal = nullptr;
    FunctionType *UnaryRetFunTy = nullptr;
    switch (LoadSize) {
    case 4:
        UnaryRetFunTy = FunctionType::get(Int32Ty, Int8PtrTy, false);
        MemVal = CallFunc(UnaryRetFunTy, "helper_fsts_" + FPR, CPUEnv);
        break;
    case 8:
        UnaryRetFunTy = FunctionType::get(Int64Ty, Int8PtrTy, false);
        MemVal = CallFunc(UnaryRetFunTy, "helper_fstl_" + FPR, CPUEnv);
        break;
    default:
        llvm_unreachable("Unsupported FPR load type");
    }
    return MemVal;
}

void X86Translator::FlushAllFPRValue() {
    for (int i = 7; i >= 0; --i) {
        FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrSTI(i)), false);
    }
}

void X86Translator::ReloadAllFPRValue() {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    for (int i = 0; i < 8; ++i) {
        StoreGMRValue(ReloadFPRValue("ST0", 8, false), X87GetCurrSTI(i));
        CallFunc(FTy, "helper_fpop", CPUEnv);
    }
}

enum FPUFlag : int {
    DEST_IS_ST0 = 1,
    MEM_VAL_IS_INT = 1 << 1,
    SHOULD_POP_ONCE = 1 << 2,
    SHOULD_POP_TWICE = 1 << 3,
};

// OneOpndModifySTN IsInt WithFPop
void X86Translator::GenFPUHelper(GuestInst *Inst, std::string Name, int Flags) {
    // assert(0 && "don't use");
    X86InstHandler InstHdl(Inst);
    bool MemValisInteger = Flags & MEM_VAL_IS_INT;
    bool DestOrFirstSrcIsST0 = Flags & DEST_IS_ST0;
    bool ShouldPopOnce = Flags & SHOULD_POP_ONCE;
    bool ShouldPopTwice = Flags & SHOULD_POP_TWICE;
    assert(InstHdl.getOpndNum() == 1 || InstHdl.getOpndNum() == 2);
    if (InstHdl.getOpndNum() == 1) {
        FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

        if (SrcOpnd.isMem()) { // e.g fadd m32fp
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            FlushFPRValue("FT0", MemVal, MemValisInteger);
            FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
            CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
            StoreGMRValue(ReloadFPRValue("ST0", 8, false), X87GetCurrST0());
        } else {
            if (DestOrFirstSrcIsST0) {
                FlushFPRValue(
                    "FT0",
                    LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID())),
                    false);
                FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()),
                              false);
                CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
                StoreGMRValue(ReloadFPRValue("ST0", 8, false), X87GetCurrST0());
            } else {
                assert(SrcOpnd.isFPR());
                FlushFPRValue("FT0", LoadGMRValue(FP64Ty, X87GetCurrST0()),
                              false);
                FlushFPRValue(
                    "ST0",
                    LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID())),
                    false);
                CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
                StoreGMRValue(ReloadFPRValue("ST0", 8, false),
                              X87GetCurrSTI(SrcOpnd.GetFPRID()));
            }
        }

        if (ShouldPopOnce) {
            X87FPR_Pop();
        }
        if (ShouldPopTwice) {
            X87FPR_Pop();
            X87FPR_Pop();
        }
    } else { // e.g fsub st0, sti means st(i) - st(0) -> st(i)
        FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
        X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
        FlushFPRValue("FT0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
        FlushFPRValue("ST0",
                      LoadGMRValue(FP64Ty, X87GetCurrSTI(DestOpnd.GetFPRID())),
                      false);
        CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
        StoreGMRValue(ReloadFPRValue("ST0", 8, false),
                      X87GetCurrSTI(DestOpnd.GetFPRID()));
    }
}

void X86Translator::translate_fabs(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            ST0->getType()),
        ST0);
    StoreGMRValue(ST0, X87GetCurrST0());
}

void X86Translator::translate_fadd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            switch (SrcOpnd.getOpndSize()) {
            case 10:
                llvm_unreachable("fadd: unhandled Mem Bitwidth 10\n");
                break;
            case 8:
                RHS = Builder.CreateBitCast(MemVal, FP64Ty);
                break;
            case 4:
                RHS = Builder.CreateBitCast(MemVal, FP32Ty);
                RHS = Builder.CreateFPExt(RHS, FP64Ty);
                break;
            default:
                llvm_unreachable("fadd: unhandled Mem Bytes\n");
            }
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        } else {
            llvm_unreachable("fadd: unhandled Opnd\n");
        }
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
        Value *res = Builder.CreateFAdd(LHS, RHS);
        StoreGMRValue(res, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd0(InstHdl.getOpnd(0));
        X86OperandHandler SrcOpnd1(InstHdl.getOpnd(1));
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd0.GetFPRID()));
        Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
        Value *res = Builder.CreateFAdd(LHS, RHS);
        StoreGMRValue(res, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
    } else {
        llvm_unreachable("fadd: unhandled Opnds\n");
    }
}

void X86Translator::translate_fiadd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *res = Builder.CreateFAdd(LHS, RHS);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_faddp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86Config::X86MappedRegsId fpi = X87GetCurrST0();
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 0) {
        fpi = X87GetCurrSTI(1);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isFPR()) {
            llvm_unreachable("faddp: Opnd err\n");
        }
        fpi = X87GetCurrSTI(SrcOpnd.GetFPRID());
    } else {
        assert(0 && "faddp: too many operands\n");
    }
    Value *LHS = LoadGMRValue(FP64Ty, fpi);
    Value *res = Builder.CreateFAdd(LHS, RHS);
    StoreGMRValue(res, fpi);
    X87FPR_Pop();
}

void X86Translator::translate_fchs(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateFNeg(ST0);
    StoreGMRValue(ST0, X87GetCurrST0());
}

void X86Translator::translate_fcomp(GuestInst *Inst) {
    FlushFPRValue("FT0", LoadGMRValue(FP64Ty, X87GetCurrSTI(1)), false);
    FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
    X87FPR_Pop();
}

void X86Translator::translate_fcompp(GuestInst *Inst) {
    FlushFPRValue("FT0", LoadGMRValue(FP64Ty, X87GetCurrSTI(1)), false);
    FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
    X87FPR_Pop();
    X87FPR_Pop();
}

void X86Translator::translate_fcomip(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg());
    FunctionType *FUCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);
    Value *STI = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrSTI(0));
    FlushFPRValue("FT0", STI, false);
    FlushFPRValue("ST0", ST0, false);
    FlushGMRValue(X86Config::EFLAG);
    CallFunc(FUCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
    X87FPR_Pop();
}

void X86Translator::translate_fcomi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg());
    FunctionType *FUCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);
    Value *STI = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrSTI(0));
    FlushFPRValue("FT0", STI, false);
    FlushFPRValue("ST0", ST0, false);
    FlushGMRValue(X86Config::EFLAG);
    CallFunc(FUCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fcom(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0);
}

void X86Translator::translate_fcos(GuestInst *Inst) {
    Value *st0 = LoadGMRValue(FP64Ty, X87GetCurrST0());

    Value *st0abs = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            st0->getType()),
        st0);

    Value *cond = Builder.CreateFCmpOLT(
        st0abs, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));
    Value *res = Builder.CreateSelect(
        cond,
        Builder.CreateCall(
            Intrinsic::getDeclaration(
                Builder.GetInsertBlock()->getParent()->getParent(),
                Intrinsic::cos, st0->getType()),
            st0),
        st0);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_f2xm1(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::exp2,
            ST0->getType()),
        ST0);
    ST0 = Builder.CreateFSub(ST0, ConstantFP::get(FP64Ty, APFloat(1.0)));
    StoreGMRValue(ST0, X87GetCurrST0());
}

void X86Translator::translate_fbld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fbld\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem());
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    CallFunc(FTy, "helper_fbld_ST0", {CPUEnv, Addr});
}

void X86Translator::translate_fbstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fbstp\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem());
    FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *FBSTTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    CallFunc(FBSTTy, "helper_fbst_ST0", {CPUEnv, Addr});
    CallFunc(FPOPTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fdecstp(GuestInst *Inst) { X87FPR_Push(); }

void X86Translator::translate_femms(GuestInst *Inst) {
    dbgs() << "Untranslated instruction femms\n";
    exit(-1);
    dbgs() << "Untranslated instruction femms\n";
    exit(-1);
}

void X86Translator::translate_ffree(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffree\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FTy, "helper_ffree_STN", {CPUEnv, SrcFPRID});
}

void X86Translator::translate_ficom(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_ficomp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT | SHOULD_POP_ONCE);
}

void X86Translator::translate_fincstp(GuestInst *Inst) { X87FPR_Pop(); }

void X86Translator::translate_fldcw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldcw\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateZExt(MemVal, Int32Ty);
    CallFunc(FTy, "helper_fldcw", {CPUEnv, MemVal});
}

void X86Translator::translate_fldenv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldenv\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fldenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fldl2e(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(1.4426950408889633870)),
                  X87GetCurrST0());
}

void X86Translator::translate_fldl2t(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(3.3219280948873621817)),
                  X87GetCurrST0());
}

void X86Translator::translate_fldlg2(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(0.3010299956639811980)),
                  X87GetCurrST0());
}

void X86Translator::translate_fldln2(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(0.6931471805599452862)),
                  X87GetCurrST0());
}

void X86Translator::translate_fldpi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(3.14159265358979323)),
                  X87GetCurrST0());
}

void X86Translator::translate_fnclex(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnclex\n";
    exit(-1);

    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fclex", CPUEnv);
}

void X86Translator::translate_fninit(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fninit\n";
    exit(-1);

    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fninit", CPUEnv);
}

void X86Translator::translate_fnop(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnop\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", {CPUEnv});
}

void X86Translator::translate_fnstcw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnstcw\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);

    Value *MemVal = CallFunc(Ty, "helper_fnstcw", CPUEnv);
    MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
    StoreOperand(MemVal, InstHdl.getOpnd(0));
}

void X86Translator::translate_fnstsw(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *Ret32Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);

    Value *MemVal = nullptr;
    if (SrcOpnd.isReg()) {
        MemVal = CallFunc(Ret32Ty, "helper_fnstsw", CPUEnv);
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        StoreGMRValue(MemVal, X86Config::EAX);
    } else if (SrcOpnd.isMem()) {
        MemVal = CallFunc(Ret32Ty, "helper_fnstsw", CPUEnv);
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        // Note: Refer to X86 Docs, there is m2bytes,
        // but capstone operand[0].size = 4, so change it.
        SrcOpnd.setOpndSize(2);
        StoreOperand(MemVal, InstHdl.getOpnd(0));
    } else {
        llvm_unreachable("fnstsw does not support opnd type\n");
    }
}

void X86Translator::translate_fpatan(GuestInst *Inst) {
    FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrSTI(1)), false);
    FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpatan", CPUEnv);
    X87FPR_Pop();
    StoreGMRValue(ReloadFPRValue("ST0", 8, false), X87GetCurrST0());
}

void X86Translator::translate_fprem(GuestInst *Inst) {
    FlushAllFPRValue();
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem", CPUEnv);
    ReloadAllFPRValue();
}

void X86Translator::translate_fprem1(GuestInst *Inst) {
    FlushAllFPRValue();
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem1", CPUEnv);
    ReloadAllFPRValue();
}

void X86Translator::translate_fptan(GuestInst *Inst) {
    FlushAllFPRValue();
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fptan_cogbt", CPUEnv);
    ReloadAllFPRValue();
}

void X86Translator::translate_ffreep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffreep\n";
    exit(-1);
}

void X86Translator::translate_frndint(GuestInst *Inst) {
    Value *st0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    st0 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(),
            Intrinsic::round, st0->getType()),
        st0);
    st0 = Builder.CreateFPToSI(st0, Int64Ty);
    StoreGMRValue(st0, X87GetCurrST0());
}

void X86Translator::translate_frstor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction frstor\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_frstor", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fnsave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnsave\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fsave", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fscale(GuestInst *Inst) {
    Value *ST1 = LoadGMRValue(FP64Ty, X87GetCurrSTI(1));
    ST1 = Builder.CreateFPToSI(ST1, Int64Ty);
    ST1 = Builder.CreateSIToFP(ST1, FP64Ty);
    ST1 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::exp2,
            ST1->getType()),
        ST1);
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    StoreGMRValue(Builder.CreateFMul(ST1, ST0), X87GetCurrST0());
}

void X86Translator::translate_fsetpm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsetpm\n";
    exit(-1);
}

void X86Translator::translate_fsincos(GuestInst *Inst) {
    FlushAllFPRValue();
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fsincos_cogbt", CPUEnv);
    ReloadAllFPRValue();
}

void X86Translator::translate_fnstenv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnstenv\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fstenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fxam(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxam\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxam_ST0", CPUEnv);
}

void X86Translator::translate_fxtract(GuestInst *Inst) {
    FlushAllFPRValue();
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxtract", CPUEnv);
    ReloadAllFPRValue();
}

void X86Translator::translate_fyl2x(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::log2,
            ST0->getType()),
        ST0);
    Value *ST1 = LoadGMRValue(FP64Ty, X87GetCurrSTI(1));
    ST0 = Builder.CreateFMul(ST1, ST0);
    StoreGMRValue(ST0, X87GetCurrSTI(1));
    X87FPR_Pop();
}

void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateFAdd(ST0, ConstantFP::get(Context, APFloat(1.0)));
    ST0 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::log2,
            ST0->getType()),
        ST0);
    Value *ST1 = LoadGMRValue(FP64Ty, X87GetCurrSTI(1));
    ST0 = Builder.CreateFMul(ST1, ST0);
    StoreGMRValue(ST0, X87GetCurrSTI(1));
    X87FPR_Pop();
}

void X86Translator::translate_fild(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(InstHdl.getOpndNum() == 1 && SrcOpnd.isMem());
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    X87FPR_Push();
    StoreGMRValue(MemVal, X87GetCurrST0());
}

void X86Translator::translate_fisttp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fisttp\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *Ret32Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);
    FunctionType *Ret64Ty = FunctionType::get(Int64Ty, Int8PtrTy, false);

    Value *MemVal = nullptr;
    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = CallFunc(Ret32Ty, "helper_fistt_ST0", CPUEnv);
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = CallFunc(Ret32Ty, "helper_fisttl_ST0", CPUEnv);
        break;
    case 8:
        MemVal = CallFunc(Ret64Ty, "helper_fisttll_ST0", CPUEnv);
        break;
    default:
        llvm_unreachable("instruction fist opnd size should (2,4,8) bytes.");
    }
    StoreOperand(MemVal, InstHdl.getOpnd(0));
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fist(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "fist: need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemValFP64 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    MemValFP64 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(),
            Intrinsic::round, MemValFP64->getType()),
        MemValFP64);
    Value *MemVal32 = Builder.CreateFPToSI(MemValFP64, Int32Ty);
    if (SrcOpnd.getOpndSize() == 2) {
        Value *MemVal16 = Builder.CreateTrunc(MemVal32, Int16Ty);
        Value *flag = Builder.CreateICmpEQ(
            MemVal32, Builder.CreateSExt(MemVal16, Int32Ty));
        MemVal32 = Builder.CreateSelect(flag, MemVal32,
                                        ConstantInt::get(Int32Ty, -32768));
        MemVal32 = Builder.CreateTrunc(MemVal32, Int16Ty);
    } else if (SrcOpnd.getOpndSize() == 4) {
        Value *flag =
            Builder.CreateICmpEQ(Builder.CreateFPToSI(MemValFP64, Int64Ty),
                                 Builder.CreateSExt(MemVal32, Int64Ty));
        MemVal32 = Builder.CreateSelect(flag, MemVal32,
                                        ConstantInt::get(Int32Ty, 0x80000000));
    } else if (SrcOpnd.getOpndSize() == 8) {
        Value *MemVal64 = Builder.CreateFPToSI(MemValFP64, Int64Ty);
        Value *flag = Builder.CreateFCmpOEQ(
            MemValFP64, Builder.CreateSIToFP(MemVal64, FP64Ty));
        MemVal32 = Builder.CreateSelect(
            flag, MemVal64, ConstantInt::get(Int64Ty, 0x8000000000000000ULL));
    } else {
        llvm_unreachable(
            "fist: instruction fist opnd size should (2,4) bytes.");
    }
    StoreOperand(MemVal32, InstHdl.getOpnd(0));
}

void X86Translator::translate_fistp(GuestInst *Inst) {
    translate_fist(Inst);
    X87FPR_Pop();
}

void X86Translator::translate_fldz(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(0.0)), X87GetCurrST0());
}

void X86Translator::translate_fld1(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(1.0)), X87GetCurrST0());
}

void X86Translator::translate_fld(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    // FunctionType *FPUSHTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    // FunctionType *FMOVTy =
    //     FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    // FunctionType *FLDTTy =
    //     FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            assert(0 && "it is developing");
            // dbgs() << "[warning]: fld use fp80\n";
            // Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
            // CallFunc(FLDTTy, "helper_fldt_ST0", {CPUEnv, Addr});
            // Value *Val = ReloadFPRValue("ST0", 8, false);
            // StoreGMRValue(Val, X87GetCurrST0());
        } else {
            X87FPR_Push();
            // Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            // FlushFPRValue("ST0", MemVal, false);
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            StoreGMRValue(MemVal, X87GetCurrST0());
        }
    } else {
        assert(SrcOpnd.isFPR());
        Value *STI = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        X87FPR_Push();
        StoreGMRValue(STI, X87GetCurrST0());
    }
}

void X86Translator::translate_fsin(GuestInst *Inst) {
    Value *st0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *st0abs = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            st0->getType()),
        st0);
    Value *cond = Builder.CreateFCmpOLT(
        st0abs, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));
    Value *res = Builder.CreateSelect(
        cond,
        Builder.CreateCall(
            Intrinsic::getDeclaration(
                Builder.GetInsertBlock()->getParent()->getParent(),
                Intrinsic::sin, st0->getType()),
            st0),
        st0);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_fsqrt(GuestInst *Inst) {
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *cond =
        Builder.CreateFCmpOGE(ST0, ConstantFP::get(FP64Ty, APFloat(0.0)));
    Value *res = Builder.CreateSelect(
        cond,
        Builder.CreateCall(
            Intrinsic::getDeclaration(
                Builder.GetInsertBlock()->getParent()->getParent(),
                Intrinsic::sqrt, ST0->getType()),
            ST0),
        ST0);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_fst(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            assert(0 && "it is developing");
            // dbgs() << "[warning]: fst use fp80\n";
            // Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
            // FlushFPRValue("ST0", ST0, false);
            // Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(),
            // false); StoreOperand(MemVal, InstHdl.getOpnd(0));
        } else if (SrcOpnd.getOpndSize() == 4) {
            Value *ST0 = LoadGMRValue(FP32Ty, X87GetCurrST0());
            StoreOperand(ST0, InstHdl.getOpnd(0));
        } else if (SrcOpnd.getOpndSize() == 8) {
            Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
            StoreOperand(ST0, InstHdl.getOpnd(0));
        } else {
            llvm_unreachable("fistp: unknown opnd size\n");
        }
    } else {
        StoreGMRValue(LoadGMRValue(FP64Ty, X87GetCurrST0()),
                      X87GetCurrSTI(SrcOpnd.GetFPRID()));
    }
}

void X86Translator::translate_fstp(GuestInst *Inst) {
    translate_fst(Inst);
    X87FPR_Pop();
}

void X86Translator::translate_fstpnce(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstpnce\n";
    exit(-1);
}

void X86Translator::translate_fxch(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    int STID = -1;
    if (InstHdl.getOpndNum() == 0) {
        STID = 1;
    } else if (InstHdl.getOpndNum() == 1) {
        assert(SrcOpnd.isFPR() && "fxch: SrcOpnd should be FPR");
        STID = SrcOpnd.GetFPRID();
    } else {
        llvm_unreachable("fxch: unhandled OpndNum");
    }
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *STN = LoadGMRValue(FP64Ty, X87GetCurrSTI(STID));
    StoreGMRValue(ST0, X87GetCurrSTI(STID));
    StoreGMRValue(STN, X87GetCurrST0());
}

void X86Translator::translate_fsubr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            switch (SrcOpnd.getOpndSize()) {
            case 10:
                llvm_unreachable("fsubr: unhandled Mem Bitwidth 10\n");
                break;
            case 8:
                RHS = Builder.CreateBitCast(MemVal, FP64Ty);
                break;
            case 4:
                RHS = Builder.CreateBitCast(MemVal, FP32Ty);
                RHS = Builder.CreateFPExt(RHS, FP64Ty);
                break;
            default:
                llvm_unreachable("fsubr: unhandled Mem Bytes\n");
            }
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        } else {
            llvm_unreachable("fsubr: unhandled SrcOpnd\n");
        }
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
        Value *res = Builder.CreateFSub(RHS, LHS);
        StoreGMRValue(res, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd0(InstHdl.getOpnd(0));
        X86OperandHandler SrcOpnd1(InstHdl.getOpnd(1));
        Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd0.GetFPRID()));
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
        Value *res = Builder.CreateFSub(RHS, LHS);
        StoreGMRValue(res, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
    } else {
        llvm_unreachable("fsubr: unhandled Opnds\n");
    }
}

void X86Translator::translate_fisubr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *res = Builder.CreateFSub(RHS, LHS);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_fsubrp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int STID = -1;
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 0) {
        STID = 1;
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        assert(InstHdl.getOpndNum() == 1);
        assert(SrcOpnd.isFPR());
        STID = SrcOpnd.GetFPRID();
    }
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(STID));
    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreGMRValue(res, X87GetCurrSTI(STID));
    X87FPR_Pop();
}

void X86Translator::translate_fsub(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            switch (SrcOpnd.getOpndSize()) {
            case 10:
                llvm_unreachable("fsub: unhandled Mem Bitwidth 10\n");
                break;
            case 8:
                RHS = Builder.CreateBitCast(MemVal, FP64Ty);
                break;
            case 4:
                RHS = Builder.CreateBitCast(MemVal, FP32Ty);
                RHS = Builder.CreateFPExt(RHS, FP64Ty);
                break;
            default:
                llvm_unreachable("fsub: unhandled Mem Bytes\n");
            }
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        } else {
            llvm_unreachable("fsub: unhandled Opnd\n");
        }
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
        Value *res = Builder.CreateFSub(LHS, RHS);
        StoreGMRValue(res, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd0(InstHdl.getOpnd(0));
        X86OperandHandler SrcOpnd1(InstHdl.getOpnd(1));
        Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd0.GetFPRID()));
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
        Value *res = Builder.CreateFSub(LHS, RHS);
        StoreGMRValue(res, X87GetCurrSTI(SrcOpnd1.GetFPRID()));
    } else {
        llvm_unreachable("fsub: unhandled Opnds\n");
    }
}

void X86Translator::translate_fisub(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_fsubp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86Config::X86MappedRegsId fpi = X87GetCurrST0();
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 0) {
        fpi = X87GetCurrSTI(1);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isFPR()) {
            llvm_unreachable("fsubp:Opnd err\n");
        }
        fpi = X87GetCurrSTI(SrcOpnd.GetFPRID());
    } else {
        assert(0 && "fsubp: too many operands\n");
    }
    Value *LHS = LoadGMRValue(FP64Ty, fpi);
    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreGMRValue(res, fpi);
    X87FPR_Pop();
}

void X86Translator::translate_ftst(GuestInst *Inst) {
    assert(0 && "Untranslated instruction ftst\n");
    FlushFPRValue("ST0", LoadGMRValue(FP64Ty, X87GetCurrST0()), false);
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fldz_FT0", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
}

void X86Translator::translate_fucomi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg());

    // FunctionType *FMOVTy =
    //     FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FUCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);
    Value *STI = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrSTI(0));
    FlushFPRValue("FT0", STI, false);
    FlushFPRValue("ST0", ST0, false);
    FlushGMRValue(X86Config::EFLAG);

    CallFunc(FUCOMITy, "helper_fucomi_ST0_FT0_cogbt", CPUEnv);
    // CallFunc(FPOPTy, "helper_fpop", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fucomip(GuestInst *Inst) {
    translate_fucomi(Inst);
    X87FPR_Pop();
}

void X86Translator::translate_fucompp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fucompp\n");
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *Binary32FunTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    Value *SrcFPRID = ConstInt(Int32Ty, 1);
    CallFunc(Binary32FunTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(UnaryFunTy, "helper_fucom_ST0_FT0", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fucomp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fucomp\n");
    GenFPUHelper(Inst, "fucom", DEST_IS_ST0 | SHOULD_POP_ONCE);
}

void X86Translator::translate_fucom(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fucom\n");
    GenFPUHelper(Inst, "fucom", DEST_IS_ST0);
}

void X86Translator::translate_wait(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", CPUEnv);
}

void X86Translator::translate_fdiv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *RHS = nullptr;
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            if (SrcOpnd.getOpndSize() == 4) {
                MemVal = Builder.CreateBitCast(MemVal, FP32Ty);
                MemVal = Builder.CreateFPExt(MemVal, FP64Ty);
            } else {
                MemVal = Builder.CreateBitCast(MemVal, FP64Ty);
            }
            RHS = MemVal;
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        }
        ST0 = Builder.CreateFDiv(ST0, RHS);
        StoreGMRValue(ST0, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        RHS = Builder.CreateFDiv(RHS, ST0);
        StoreGMRValue(RHS, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    } else {
        llvm_unreachable("fdiv: unhandled OpndNum\n");
    }
}

void X86Translator::translate_fidiv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateFDiv(ST0, MemVal);
    StoreGMRValue(ST0, X87GetCurrST0());
}

void X86Translator::translate_fdivp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int stri = -1;
    if (InstHdl.getOpndNum() == 0) {
        stri = 1;
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        stri = SrcOpnd.GetFPRID();
    }
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(stri));
    RHS = Builder.CreateFDiv(RHS, ST0);
    StoreGMRValue(RHS, X87GetCurrSTI(stri));
    X87FPR_Pop();
}

void X86Translator::GenFCMOVHelper(GuestInst *Inst, std::string LBTIntrinic) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, LBTIntrinic);
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);

    BasicBlock *MovBB = BasicBlock::Create(Context, "MovBB", TransFunc, ExitBB);
    BasicBlock *NotMovBB =
        BasicBlock::Create(Context, "NotMovBB", TransFunc, ExitBB);

    SyncAllGMRValue();
    Builder.CreateCondBr(Cond, MovBB, NotMovBB);

    Builder.SetInsertPoint(MovBB);
    FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    X86OperandHandler STIOpnd(InstHdl.getOpnd(0));
    // Value *SrcFPRID = ConstInt(Int32Ty, STIOpnd.GetFPRID());
    // CallFunc(FTy, "helper_fmov_ST0_STN", {CPUEnv, SrcFPRID});
    StoreGMRValue(LoadGMRValue(FP64Ty, X87GetCurrSTI(STIOpnd.GetFPRID())),
                  X87GetCurrST0());
    SyncAllGMRValue();
    Builder.CreateBr(NotMovBB);

    Builder.SetInsertPoint(NotMovBB);
}

void X86Translator::translate_fcmovbe(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjbe");
}

void X86Translator::translate_fcmovb(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjb");
}

void X86Translator::translate_fcmove(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setje");
}

void X86Translator::translate_fcmovnbe(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setja");
}

void X86Translator::translate_fcmovnb(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjae");
}

void X86Translator::translate_fcmovne(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjne");
}

void X86Translator::translate_fcmovnu(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjnp");
}

void X86Translator::translate_fcmovu(GuestInst *Inst) {
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjp");
}

void X86Translator::translate_fmul(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            switch (SrcOpnd.getOpndSize()) {
            case 10:
                llvm_unreachable("fmul: unhandled Mem Bitwidth 10\n");
                break;
            case 8:
                RHS = Builder.CreateBitCast(MemVal, FP64Ty);
                break;
            case 4:
                RHS = Builder.CreateBitCast(MemVal, FP32Ty);
                RHS = Builder.CreateFPExt(RHS, FP64Ty);
                break;
            default:
                llvm_unreachable("fmul: unhandled Mem Bytes\n");
            }
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        }
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
        Value *res = Builder.CreateFMul(LHS, RHS);
        StoreGMRValue(res, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
        Value *res = Builder.CreateFMul(LHS, RHS);
        StoreGMRValue(res, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    } else {
        llvm_unreachable("fmul: unhandled Opnds\n");
    }
}

void X86Translator::translate_fimul(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *res = Builder.CreateFMul(LHS, RHS);
    StoreGMRValue(res, X87GetCurrST0());
}

void X86Translator::translate_fmulp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int FPi = -1;
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 0) {
        FPi = 1;
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isFPR()) {
            llvm_unreachable("fmulp: Opnd err\n");
        }
        FPi = SrcOpnd.GetFPRID();
    }
    Value *LHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(FPi));
    Value *res = Builder.CreateFMul(LHS, RHS);
    StoreGMRValue(res, X87GetCurrSTI(FPi));
    X87FPR_Pop();
}

void X86Translator::translate_fdivr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *RHS = nullptr;
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (SrcOpnd.isMem()) {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            if (SrcOpnd.getOpndSize() == 4) {
                MemVal = Builder.CreateBitCast(MemVal, FP32Ty);
                MemVal = Builder.CreateFPExt(MemVal, FP64Ty);
            } else {
                MemVal = Builder.CreateBitCast(MemVal, FP64Ty);
            }
            RHS = MemVal;
        } else if (SrcOpnd.isFPR()) {
            RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        }
        ST0 = Builder.CreateFDiv(RHS, ST0);
        StoreGMRValue(ST0, X87GetCurrST0());
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(SrcOpnd.GetFPRID()));
        RHS = Builder.CreateFDiv(ST0, RHS);
        StoreGMRValue(RHS, X87GetCurrSTI(SrcOpnd.GetFPRID()));
    } else {
        llvm_unreachable("fdiv: unhandled OpndNum\n");
    }
}

void X86Translator::translate_fidivr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    ST0 = Builder.CreateFDiv(MemVal, ST0);
    StoreGMRValue(ST0, X87GetCurrST0());
}

void X86Translator::translate_fdivrp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    int stri = -1;
    if (InstHdl.getOpndNum() == 0) {
        stri = 1;
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        stri = SrcOpnd.GetFPRID();
    }
    Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
    Value *RHS = LoadGMRValue(FP64Ty, X87GetCurrSTI(stri));
    RHS = Builder.CreateFDiv(ST0, RHS);
    StoreGMRValue(RHS, X87GetCurrSTI(stri));
    X87FPR_Pop();
}
