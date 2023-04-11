#include "emulator.h"
#include "x86-translator.h"

Value *X86Translator::getFT0Ptr() {
    Value *FT0Ptr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int32Ty, GuestFT0Offset()));
    FT0Ptr = Builder.CreateBitCast(FT0Ptr, FP64PtrTy);
    return FT0Ptr;
}

void X86Translator::FP64CompareSW(Value *LHS, Value *RHS) {
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_0 = nullptr;
    Value *C_3 = nullptr;
    C_3 = Builder.CreateFCmpOEQ(LHS, RHS);
    C_0 = Builder.CreateFCmpOGT(LHS, RHS); // SRC>ST0
    C_0 = Builder.CreateZExt(C_0, Int16Ty);
    C_3 = Builder.CreateZExt(C_3, Int16Ty);
    C_0 = Builder.CreateShl(C_0, ConstInt(Int16Ty, 8));
    C_3 = Builder.CreateShl(C_3, ConstInt(Int16Ty, 14));
    old_flag = Builder.CreateAnd(old_flag, ConstInt(Int16Ty, 0xbaff));
    old_flag = Builder.CreateOr(old_flag, C_0);
    old_flag = Builder.CreateOr(old_flag, C_3);
    Builder.CreateStore(old_flag, FpusPtr);
}

void X86Translator::FP64CompareEFLAG(Value *LHS, Value *RHS) {
    FlushGMRValue(X86Config::EFLAG);
    Value *EflgPtr = Builder.CreateGEP(Int8Ty, CPUEnv,
                                       ConstInt(Int32Ty, GuestEflagOffset()));
    EflgPtr = Builder.CreateBitCast(EflgPtr, Int32PtrTy);
    Value *old_flag = Builder.CreateLoad(Int32Ty, EflgPtr);
    Value *CF = nullptr;
    Value *ZF = nullptr;
    ZF = Builder.CreateFCmpOEQ(LHS, RHS);
    CF = Builder.CreateFCmpOGT(LHS, RHS); // SRC>ST0
    CF = Builder.CreateZExt(CF, Int32Ty);
    ZF = Builder.CreateZExt(ZF, Int32Ty);
    ZF = Builder.CreateShl(ZF, ConstInt(Int32Ty, 6));
    old_flag = Builder.CreateAnd(old_flag, ConstInt(Int32Ty, 0xffffffba));
    old_flag = Builder.CreateOr(old_flag, CF);
    old_flag = Builder.CreateOr(old_flag, ZF);
    Builder.CreateStore(old_flag, EflgPtr);
    ReloadGMRValue(X86Config::EFLAG);
}

Value *X86Translator::GetFpusPtr(void) {
    Value *FpusPtr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int32Ty, GuestFpusOffset()));
    FpusPtr = Builder.CreateBitCast(FpusPtr, Int16PtrTy);
    return FpusPtr;
}

Value *X86Translator::GetFpucPtr(void) {
    Value *FpucPtr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int32Ty, GuestFpucOffset()));
    FpucPtr = Builder.CreateBitCast(FpucPtr, Int16PtrTy);
    return FpucPtr;
}

Value *X86Translator::getPrecisonCtrl(void) {
    Value *FpucPtr = GetFpucPtr();
    Value *Fpuc = Builder.CreateLoad(Int16Ty, FpucPtr);
    Value *prec = Builder.CreateLShr(Fpuc, ConstInt(Int16Ty, 8)); // 8
    prec = Builder.CreateAnd(Fpuc, ConstInt(Int16Ty, 0x0003));
    return prec;
}

void X86Translator::SetFPTag(Value *fpi, uint8_t v) {
    Value *FPTagIdxOff =
        Builder.CreateMul(fpi, ConstantInt::get(Int32Ty, GuestFpTagSize()));
    Value *FPTagAddr = Builder.CreateAdd(
        ConstantInt::get(Int32Ty, GuestFpTagOffset()), FPTagIdxOff);
    Value *FPTagPtr = Builder.CreateGEP(Int8Ty, CPUEnv, FPTagAddr);
    Builder.CreateStore(ConstantInt::get(Int8Ty, v), FPTagPtr);
}

Value *X86Translator::GetFPRPtr(Value *fpi, Type *FPRPtrType) {
    Value *FPRIdxOff =
        Builder.CreateMul(fpi, ConstInt(Int32Ty, GuestFPRegSize()));
    Value *FPROff = Builder.CreateAdd(
        FPRIdxOff, ConstantInt::get(Int32Ty, GuestFpregsOffset())); // add
    Value *FPRAddr =
        Builder.CreateGEP(Int8Ty, CPUEnv, FPROff); // fpreg[0] address in RAM
    Value *FPRPtr =
        Builder.CreateBitCast(FPRAddr, FPRPtrType); // transform to Ptr of INT32
    return FPRPtr;
}

void X86Translator::StoreToFPR(Value *V, Value *fpi) {
    Value *FPRPtr = GetFPRPtr(fpi, V->getType()->getPointerTo());
    Builder.CreateStore(V, FPRPtr);
}

Value *X86Translator::LoadFromFPR(Value *fpi, Type *FPRType) {
    Value *FPRPtr = GetFPRPtr(fpi, FPRType->getPointerTo());
    return Builder.CreateLoad(FPRType, FPRPtr);
}

void X86Translator::SetFPUTop(Value *fpi) {
    // Load fpstt from CPUX86State.
    int Off = GuestFpsttOffset();
    Value *FpsttAddr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int32Ty, Off));
    Value *Ptr = Builder.CreateBitCast(FpsttAddr, Int32PtrTy);
    Builder.CreateStore(fpi, Ptr);
}

Value *X86Translator::GetFPUTop(void) {
    Value *FpsttAddr = Builder.CreateGEP(
        Int8Ty, CPUEnv,
        ConstantInt::get(Int32Ty, GuestFpsttOffset())); // fpstt address in RAM
    Value *FpsttPtr = Builder.CreateBitCast(
        FpsttAddr, Int32PtrTy); // transform to Ptr of INT32PTR
    Value *Fpstt =
        Builder.CreateLoad(Int32Ty, FpsttPtr); // get the Value of top
    return Fpstt;
}

void X86Translator::FlushFPRValue(std::string FPR, Value *FV, bool isInt) {
    FunctionType *FuncTy = nullptr;
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

enum FPUFlag : int {
    DEST_IS_ST0 = 1,
    MEM_VAL_IS_INT = 1 << 1,
    SHOULD_POP_ONCE = 1 << 2,
    SHOULD_POP_TWICE = 1 << 3,
};

// OneOpndModifySTN IsInt WithFPop
void X86Translator::GenFPUHelper(GuestInst *Inst, std::string Name, int Flags) {
    X86InstHandler InstHdl(Inst);
    bool MemValisInteger = Flags & MEM_VAL_IS_INT;
    bool DestOrFirstSrcIsST0 = Flags & DEST_IS_ST0;
    bool ShouldPopOnce = Flags & SHOULD_POP_ONCE;
    bool ShouldPopTwice = Flags & SHOULD_POP_TWICE;

    assert(InstHdl.getOpndNum() == 1 || InstHdl.getOpndNum() == 2);
    if (InstHdl.getOpndNum() == 1) {
        FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
        FunctionType *FTy2 =
            FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

        if (SrcOpnd.isMem()) { // e.g fadd m32fp
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            FlushFPRValue("FT0", MemVal, MemValisInteger);
            CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
        } else {
            if (DestOrFirstSrcIsST0) {
                // DestOpnd is st(0) e.g fsub st(1) means st(0) - st(1) -> st(0)
                Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
                CallFunc(FTy2, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
                CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
            } else {
                // DestOpnd is SrcOpnd and another SrcOpnd is st(0) like faddp
                Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
                CallFunc(FTy2, "helper_" + Name + "_STN_ST0",
                         {CPUEnv, DestFPRID});
            }
        }

        if (ShouldPopOnce)
            CallFunc(FTy, "helper_fpop", CPUEnv);
        if (ShouldPopTwice) {
            CallFunc(FTy, "helper_fpop", CPUEnv);
            CallFunc(FTy, "helper_fpop", CPUEnv);
        }
    } else { // e.g fsub st0, sti means st(i) - st(0) -> st(i)
        FunctionType *FTy2 =
            FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
        Value *DestFPRID = ConstInt(Int32Ty, DestOpnd.GetSTRID());
        assert(DestFPRID);
        CallFunc(FTy2, "helper_" + Name + "_STN_ST0", {CPUEnv, DestFPRID});
    }
}

// void X86Translator::translate_fabs(GuestInst *Inst) {
//     FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FuncTy, "helper_fabs_ST0", CPUEnv);
// }

void X86Translator::translate_fabs(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fabs\n";
    Value *top = GetFPUTop();
    Value *Vst0 = LoadFromFPR(top, FP64Ty);
    Value *absVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            Vst0->getType()),
        Vst0);
    StoreToFPR(absVal, top);

    // set C1 to 0
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_1 = ConstInt(Int16Ty, 0xfdff);
    old_flag = Builder.CreateAnd(old_flag, C_1);
    Builder.CreateStore(old_flag, FpusPtr);
}

// void X86Translator::translate_fadd(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fadd", DEST_IS_ST0);
// }

void X86Translator::translate_fadd(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fadd\n";
    X86InstHandler InstHdl(Inst);

    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *St0 = GetFPUTop();
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        Value *DestSTRID = nullptr;
        if (SrcOpnd.isMem()) {
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
        } else if (SrcOpnd.isSTR()) {
            DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFAdd(LHS, RHS);
        StoreToFPR(res, St0);
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *St0 = GetFPUTop();
        Value *RHS = nullptr;
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        RHS = LoadFromFPR(DestFPRID, FP64Ty);
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFAdd(LHS, RHS);
        StoreToFPR(res, DestFPRID);
    } else {
        llvm_unreachable("fadd: unhandled Opnds\n");
    }
    // TODO: merge_exception_flags
}

// void X86Translator::translate_fiadd(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1 &&
//            "fiadd does not support opnd number!\n");
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.isMem() && "fiadd opnd must mem!\n");
//     GenFPUHelper(Inst, "fadd", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

// now add as signed int
void X86Translator::translate_fiadd(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fiadd\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);

    Value *St0 = GetFPUTop();
    Value *LHS = LoadFromFPR(St0, FP64Ty);

    Value *res = Builder.CreateFAdd(LHS, RHS);
    StoreToFPR(res, St0);
}

// void X86Translator::translate_faddp(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1 && "faddp does not support opnd
//     number\n"); GenFPUHelper(Inst, "fadd", SHOULD_POP_ONCE);
// }

void X86Translator::translate_faddp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_faddp\n";
    X86InstHandler InstHdl(Inst);
    Value *St0 = GetFPUTop();
    Value *FPi = nullptr;
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    if (InstHdl.getOpndNum() == 0) {
        FPi = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isSTR()) {
            llvm_unreachable("faddp:Opnd err\n");
        }
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        FPi = Builder.CreateAdd(St0, DestSTRID);
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    }
    Value *LHS = LoadFromFPR(FPi, FP64Ty);
    Value *res = Builder.CreateFAdd(LHS, RHS);
    StoreToFPR(res, FPi);
    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fchs(GuestInst *Inst) {
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fchs_ST0", {CPUEnv});
// }

void X86Translator::translate_fchs(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fchs\n";
    Value *top = GetFPUTop();
    Value *Vst0 = LoadFromFPR(top, FP64Ty);
    Vst0 = Builder.CreateFNeg(Vst0);
    StoreToFPR(Vst0, top);
}

// void X86Translator::translate_fcomp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | SHOULD_POP_ONCE);
// }

void X86Translator::translate_fcomp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcomp\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();

    if (InstHdl.getOpndNum() == 0) {
        Value *ST1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        ST1 = Builder.CreateAnd(ST1, ConstInt(Int32Ty, 7));
        LHS = LoadFromFPR(ST1, FP64Ty);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));

        if (SrcOpnd.getOpndSize() == 8 || SrcOpnd.isSTR()) {
            LHS = Builder.CreateBitCast(MemVal, FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateBitCast(MemVal, FP32Ty);
            LHS = Builder.CreateFPExt(LHS, FP64Ty);
        } else {
            llvm_unreachable("fcomp: Opnd Bitwidth\n");
        }
    } else {
        llvm_unreachable("fcomp: Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);
    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fcompp(GuestInst *Inst) {
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *Binary32FunTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     Value *SrcFPRID = ConstInt(Int32Ty, 1);
//     CallFunc(Binary32FunTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
// }

void X86Translator::translate_fcompp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcompp\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 0) {
        llvm_unreachable("fcompp: only handle no Opnd\n");
    }

    Value *St0 = GetFPUTop();
    Value *St1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St1 = Builder.CreateAnd(St1, ConstInt(Int32Ty, 7));
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    Value *LHS = LoadFromFPR(St1, FP64Ty);

    FP64CompareSW(LHS, RHS);

    SetFPTag(St1, 1);
    St1 = Builder.CreateAdd(St1, ConstInt(Int32Ty, 1));
    St1 = Builder.CreateAnd(St1, ConstInt(Int32Ty, 7));
    SetFPTag(St1, 1);
    SetFPUTop(St1);
}

// void X86Translator::translate_fcomip(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1);

//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.isReg() && "operand of fcomip must be fpr");
//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);

//     FlushGMRValue(X86Config::EFLAG);
//     Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
//     CallFunc(FPOPTy, "helper_fpop", CPUEnv);
//     ReloadGMRValue(X86Config::EFLAG);
// }

void X86Translator::translate_fcomip(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcomip\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 1) {
        llvm_unreachable("fcomip: only handle one Opnd\n");
    }
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *LHS = Builder.CreateBitCast(MemVal, FP64Ty);
    Value *St0 = GetFPUTop();
    Value *RHS = LoadFromFPR(St0, FP64Ty);

    FP64CompareEFLAG(LHS, RHS);

    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fcomi(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1);

//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.isReg() && "operand of fcomi must be fpr");
//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);

//     FlushGMRValue(X86Config::EFLAG);
//     Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
//     ReloadGMRValue(X86Config::EFLAG);
// }

void X86Translator::translate_fcomi(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcomi\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 1) {
        llvm_unreachable("fcomi: only handle one Opnd\n");
    }
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateBitCast(MemVal, FP64Ty);
    Value *St0 = GetFPUTop();
    Value *RHS = LoadFromFPR(St0, FP64Ty);

    FP64CompareEFLAG(MemVal, RHS);
}

// void X86Translator::translate_fcom(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fcom", DEST_IS_ST0);
// }

void X86Translator::translate_fcom(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcom\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();

    if (InstHdl.getOpndNum() == 0) {
        Value *ST1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        ST1 = Builder.CreateAnd(ST1, ConstInt(Int32Ty, 7));
        LHS = LoadFromFPR(ST1, FP64Ty);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));

        if (SrcOpnd.getOpndSize() == 8 || SrcOpnd.isSTR()) {
            LHS = Builder.CreateBitCast(MemVal, FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateBitCast(MemVal, FP32Ty);
            LHS = Builder.CreateFPExt(LHS, FP64Ty);
        } else {
            llvm_unreachable("fcom: Opnd Bitwidth\n");
        }
    } else {
        llvm_unreachable("fcom Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);
}

// void X86Translator::translate_fcos(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fcos\n";
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fcos", CPUEnv);
// }

void X86Translator::translate_fcos(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fcos\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);

    Value *ABS = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            MemVal->getType()),
        MemVal);

    BasicBlock *LessBB = BasicBlock::Create(Context, "Less", TransFunc, ExitBB);
    BasicBlock *LargBB = BasicBlock::Create(Context, "Larg", TransFunc, ExitBB);
    BasicBlock *EndBB = BasicBlock::Create(Context, "End", TransFunc, ExitBB);
    Value *Cond = Builder.CreateFCmpOLT(
        ABS, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));

    Builder.CreateCondBr(Cond, LessBB, LargBB);

    /*---------------------------------------------*/
    Builder.SetInsertPoint(LessBB);

    Value *TOP = GetFPUTop();
    Value *V = LoadFromFPR(TOP, FP64Ty);

    Value *FpusPtr_1 = GetFpusPtr();
    Value *old_flag_1 = Builder.CreateLoad(Int16Ty, FpusPtr_1);
    Value *C_2_1 = nullptr;

    V = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::cos,
            V->getType()),
        V);

    // set C2 to 0

    C_2_1 = ConstInt(Int16Ty, 0xfbff);
    old_flag_1 = Builder.CreateAnd(old_flag_1, C_2_1);
    Builder.CreateStore(old_flag_1, FpusPtr_1);

    StoreToFPR(V, TOP);

    Builder.CreateBr(EndBB);
    /*---------------------------------------------*/
    Builder.SetInsertPoint(LargBB);

    // set C2 to 1
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_2 = nullptr;
    C_2 = ConstInt(Int16Ty, 0x0400);
    old_flag = Builder.CreateOr(old_flag, C_2);
    Builder.CreateStore(old_flag, FpusPtr);

    Builder.CreateBr(EndBB);

    /*---------------------------------------------*/

    Builder.SetInsertPoint(EndBB);
}

// void X86Translator::translate_f2xm1(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_f2xm1\n";
//     FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FuncTy, "helper_f2xm1", {CPUEnv});
// }

void X86Translator::translate_f2xm1(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_f2xm1\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::exp2,
            MemVal->getType()),
        MemVal);
    MemVal = Builder.CreateFSub(MemVal, ConstantFP::get(FP64Ty, APFloat(1.0)));

    StoreToFPR(MemVal, top);
}

void X86Translator::translate_fbld(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fbld\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem());
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    CallFunc(FTy, "helper_fbld_ST0", {CPUEnv, Addr});
}

void X86Translator::translate_fbstp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fbstp\n";
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

// void X86Translator::translate_fdecstp(GuestInst *Inst) {
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fdecstp", CPUEnv);
// }

void X86Translator::translate_fdecstp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fdecstp\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    SetFPUTop(newtop);
}

void X86Translator::translate_femms(GuestInst *Inst) {
    dbgs() << "Untranslated instruction femms\n";
    exit(-1);
}

// void X86Translator::translate_ffree(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty},
//     false); Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FTy, "helper_ffree_STN", {CPUEnv, SrcFPRID});
// }

void X86Translator::translate_ffree(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_ffree\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *SrcFPRID = ConstInt(Int8Ty, SrcOpnd.GetSTRID());
    SetFPTag(SrcFPRID, 1);
}

// void X86Translator::translate_ficom(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_ficom(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_ficom\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        if (SrcOpnd.getOpndSize() == 2 || SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateZExt(MemVal, Int64Ty);
            LHS = Builder.CreateSIToFP(MemVal, FP64Ty);
        } else {
            llvm_unreachable("ficom: Opnd Bitwidth\n");
        }
    } else {
        llvm_unreachable("ficom Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);
}

// void X86Translator::translate_ficomp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT |
//     SHOULD_POP_ONCE);
// }

void X86Translator::translate_ficomp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_ficomp\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();

    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        if (SrcOpnd.getOpndSize() == 2 || SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateZExt(MemVal, Int64Ty);
            LHS = Builder.CreateSIToFP(MemVal, FP64Ty);
        } else {
            llvm_unreachable("ficomp Opnd Bitwidth err\n");
        }
    } else {
        llvm_unreachable("ficomp Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);

    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fincstp(GuestInst *Inst) {
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fincstp", CPUEnv);
// }

void X86Translator::translate_fincstp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fincstp\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateAdd(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    SetFPUTop(newtop);
}

void X86Translator::translate_fldcw(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateZExt(MemVal, Int32Ty);
    CallFunc(FTy, "helper_fldcw", {CPUEnv, MemVal});
}

// void X86Translator::translate_fldcw(GuestInst *Inst) {
//      //dbgs() << "ENTRY translate_fldcw\n";
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.getOpndSize() == 2);
//     Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
//     Builder.CreateStore(MemVal, GetFpucPtr());
//     // TODO
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_round_mode", CPUEnv);
// }

void X86Translator::translate_fldenv(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldenv\n";
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fldenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

// void X86Translator::translate_fldl2e(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldl2e_ST0", {CPUEnv});
// }

void X86Translator::translate_fldl2e(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldl2e\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(Context, APFloat(1.4426950408889633870)),
               newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fldl2t(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldl2t_ST0", {CPUEnv});
// }

void X86Translator::translate_fldl2t(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldl2t\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(Context, APFloat(3.3219280948873621817)),
               newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fldlg2(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldlg2_ST0", {CPUEnv});
// }

void X86Translator::translate_fldlg2(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldlg2\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(Context, APFloat(0.3010299956639811980)),
               newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fldln2(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldln2_ST0", {CPUEnv});
// }

void X86Translator::translate_fldln2(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldln2\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(Context, APFloat(0.6931471805599452862)),
               newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fldpi(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldpi_ST0", {CPUEnv});
// }

void X86Translator::translate_fldpi(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldpi\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(Context, APFloat(3.14159265358979323)), newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

void X86Translator::translate_fnclex(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnclex\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fclex", CPUEnv);
}

void X86Translator::translate_fninit(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fninit\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fninit", CPUEnv);
}

void X86Translator::translate_fnop(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnop\n";
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", {CPUEnv});
}

void X86Translator::translate_fnstcw(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnstcw\n";

    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);

    Value *MemVal = CallFunc(Ty, "helper_fnstcw", CPUEnv);
    MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
    StoreOperand(MemVal, InstHdl.getOpnd(0));
}

// void X86Translator::translate_fnstcw(GuestInst *Inst) {
//      //dbgs() << "ENTRY translate_fnstcw\n";
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

//     Value *fpuc = Builder.CreateLoad(Int16Ty, GetFpucPtr());
//     StoreOperand(fpuc, InstHdl.getOpnd(0));
// }

void X86Translator::translate_fnstsw(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnstsw\n";
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
        dbgs() << "fnstsw does not support opnd type\n";
        exit(-1);
    }
}

// void X86Translator::translate_fpatan(GuestInst *Inst) {
//      //dbgs() << "ENTRY translate_fpatan\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpatan", CPUEnv);
// }

void X86Translator::translate_fpatan(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fpatan\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpatan_math_64", CPUEnv);
    Value *newtop = GetFPUTop();
    SetFPTag(newtop, 1);
    newtop = Builder.CreateAdd(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    SetFPUTop(newtop);
}

// void X86Translator::translate_fprem(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fprem\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fprem", CPUEnv);
// }

void X86Translator::translate_fprem(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fprem\n";

    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    Value *st1 = Builder.CreateAdd(top, ConstInt(Int32Ty, 1));
    st1 = Builder.CreateAnd(st1, ConstInt(Int32Ty, 7));
    Value *res = LoadFromFPR(st1, FP64Ty);
    res = Builder.CreateFRem(MemVal, res);
    StoreToFPR(res, top);
}

void X86Translator::translate_fprem1(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fprem1\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem1", CPUEnv);
}

// void X86Translator::translate_fptan(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fptan\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fptan", CPUEnv);
// }

void X86Translator::translate_fptan(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fptan\n";

    Value *Top = GetFPUTop();
    Value *Val = LoadFromFPR(Top, FP64Ty);

    BasicBlock *LessBB = BasicBlock::Create(Context, "Less", TransFunc, ExitBB);
    BasicBlock *LargBB = BasicBlock::Create(Context, "Larg", TransFunc, ExitBB);
    BasicBlock *EndBB = BasicBlock::Create(Context, "End", TransFunc, ExitBB);
    Value *Cond = Builder.CreateFCmpOLT(
        Val, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));

    Builder.CreateCondBr(Cond, LessBB, LargBB);

    /*---------------------------------------------*/
    Builder.SetInsertPoint(LessBB);

    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    Value *Vcos = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::cos,
            MemVal->getType()),
        MemVal);

    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::sin,
            MemVal->getType()),
        MemVal);

    MemVal = Builder.CreateFDiv(MemVal, Vcos);
    StoreToFPR(MemVal, top);

    top = Builder.CreateSub(top, ConstInt(Int32Ty, 1));
    top = Builder.CreateAnd(top, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(FP64Ty, APFloat(1.0)), top);
    SetFPUTop(top);
    SetFPTag(top, 0);

    // set C2 to 0
    Value *FpusPtr_1 = GetFpusPtr();
    Value *old_flag_1 = Builder.CreateLoad(Int16Ty, FpusPtr_1);
    Value *C_2_1 = ConstInt(Int16Ty, 0xfbff);
    old_flag_1 = Builder.CreateAnd(old_flag_1, C_2_1);
    Builder.CreateStore(old_flag_1, FpusPtr_1);

    Builder.CreateBr(EndBB);
    /*---------------------------------------------*/
    Builder.SetInsertPoint(LargBB);

    // set C2 to 1
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_2 = nullptr;
    C_2 = ConstInt(Int16Ty, 0x0400);
    old_flag = Builder.CreateOr(old_flag, C_2);
    Builder.CreateStore(old_flag, FpusPtr);

    Builder.CreateBr(EndBB);

    /*---------------------------------------------*/

    Builder.SetInsertPoint(EndBB);
}

void X86Translator::translate_ffreep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffreep\n";
    exit(-1);
}

// void X86Translator::translate_frndint(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_frndint\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_frndint", CPUEnv);
// }

void X86Translator::translate_frndint(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_frndint\n";
    Value *top = GetFPUTop();

    Value *MemVal = LoadFromFPR(top, FP64Ty);

    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(),
            Intrinsic::round, MemVal->getType()),
        MemVal);
    MemVal = Builder.CreateFPToSI(MemVal, Int64Ty);
    StoreToFPR(MemVal, top);
}

void X86Translator::translate_frstor(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_frstor\n";
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_frstor", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fnsave(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnsave\n";
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fsave", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

// void X86Translator::translate_fscale(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fscale\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fscale", CPUEnv);
// }

void X86Translator::translate_fscale(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fscale\n";
    Value *top = GetFPUTop();
    Value *STi = Builder.CreateAdd(top, ConstInt(Int32Ty, 1));
    STi = Builder.CreateAnd(STi, ConstInt(Int32Ty, 7));
    Value *ST1 = LoadFromFPR(STi, FP64Ty);
    ST1 = Builder.CreateFPToSI(ST1, Int64Ty);

    ST1 = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::exp2,
            ST1->getType()),
        ST1);

    ST1 = Builder.CreateSIToFP(ST1, FP64Ty);

    Value *MemVal = LoadFromFPR(top, FP64Ty);

    StoreToFPR(MemVal, top);
}

void X86Translator::translate_fsetpm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsetpm\n";
    exit(-1);
}

// void X86Translator::translate_fsincos(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fsincos\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fsincos", CPUEnv);
// }

void X86Translator::translate_fsincos(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsincos\n";

    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);

    BasicBlock *LessBB = BasicBlock::Create(Context, "Less", TransFunc, ExitBB);
    BasicBlock *LargBB = BasicBlock::Create(Context, "Larg", TransFunc, ExitBB);
    BasicBlock *EndBB = BasicBlock::Create(Context, "End", TransFunc, ExitBB);

    Value *Cond = Builder.CreateFCmpOLT(
        MemVal, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));
    Builder.CreateCondBr(Cond, LessBB, LargBB);

    /*---------------------------------------------*/
    Builder.SetInsertPoint(LessBB);

    Value *TOP = GetFPUTop();
    Value *V = LoadFromFPR(TOP, FP64Ty);

    Value *FpusPtr_1 = GetFpusPtr();
    Value *old_flag_1 = Builder.CreateLoad(Int16Ty, FpusPtr_1);
    Value *C_2_1 = nullptr;

    Value *Vsin = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::sin,
            V->getType()),
        V);

    StoreToFPR(Vsin, TOP);

    V = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::cos,
            V->getType()),
        V);

    TOP = Builder.CreateSub(TOP, ConstInt(Int32Ty, 1));
    TOP = Builder.CreateAnd(TOP, ConstInt(Int32Ty, 7));
    SetFPUTop(TOP);
    SetFPTag(TOP, 0);
    StoreToFPR(V, TOP);

    // set C2 to 0

    C_2_1 = ConstInt(Int16Ty, 0xfbff);
    old_flag_1 = Builder.CreateAnd(old_flag_1, C_2_1);
    Builder.CreateStore(old_flag_1, FpusPtr_1);

    Builder.CreateBr(EndBB);
    /*---------------------------------------------*/
    Builder.SetInsertPoint(LargBB);

    // set C2 to 1
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_2 = nullptr;
    C_2 = ConstInt(Int16Ty, 0x0400);
    old_flag = Builder.CreateOr(old_flag, C_2);
    Builder.CreateStore(old_flag, FpusPtr);

    Builder.CreateBr(EndBB);

    /*---------------------------------------------*/

    Builder.SetInsertPoint(EndBB);
}

void X86Translator::translate_fnstenv(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fnstenv\n";
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fstenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fxam(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fxam\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxam", CPUEnv);
}

void X86Translator::translate_fxtract(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fxtract\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxtract", CPUEnv);
}

// void X86Translator::translate_fyl2x(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fyl2x\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fyl2x", CPUEnv);
// }

void X86Translator::translate_fyl2x(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fyl2x\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::log2,
            MemVal->getType()),
        MemVal);
    Value *sti = Builder.CreateAdd(top, ConstInt(Int32Ty, 1));
    sti = Builder.CreateAnd(sti, ConstInt(Int32Ty, 7));
    Value *ST1 = LoadFromFPR(sti, FP64Ty);
    MemVal = Builder.CreateFMul(ST1, MemVal);
    StoreToFPR(MemVal, sti);
    SetFPTag(top, 1);
    SetFPUTop(sti);
}

// void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fyl2xp1\n";
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fyl2xp1", CPUEnv);
// }

void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fyl2xp1\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    MemVal = Builder.CreateFAdd(MemVal, ConstantFP::get(Context, APFloat(1.0)));
    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::log2,
            MemVal->getType()),
        MemVal);
    Value *sti = Builder.CreateAdd(top, ConstInt(Int32Ty, 1));
    sti = Builder.CreateAnd(sti, ConstInt(Int32Ty, 7));
    Value *ST1 = LoadFromFPR(sti, FP64Ty);
    MemVal = Builder.CreateFMul(ST1, MemVal);
    StoreToFPR(MemVal, sti);
    SetFPTag(top, 1);
    SetFPUTop(sti);
}

// void X86Translator::translate_fild(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(InstHdl.getOpndNum() == 1 && SrcOpnd.isMem());
//     Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
//     FlushFPRValue("ST0", MemVal, true);
// }

void X86Translator::translate_fild(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fild\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(InstHdl.getOpndNum() == 1 && SrcOpnd.isMem());
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *NewSt0 = GetFPUTop();
    NewSt0 = Builder.CreateSub(NewSt0, ConstInt(Int32Ty, 1));
    NewSt0 = Builder.CreateAnd(NewSt0, ConstInt(Int32Ty, 7));
    StoreToFPR(MemVal, NewSt0);
    SetFPUTop(NewSt0);
    SetFPTag(NewSt0, 0);
    // TODO: set_floatx80_rounding_precision
}

// void X86Translator::translate_fisttp(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1 && "need one Opnd");
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *Ret32Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);
//     FunctionType *Ret64Ty = FunctionType::get(Int64Ty, Int8PtrTy, false);

//     Value *MemVal = nullptr;
//     switch (SrcOpnd.getOpndSize()) {
//     case 2:
//         MemVal = CallFunc(Ret32Ty, "helper_fistt_ST0", CPUEnv);
//         MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
//         break;
//     case 4:
//         MemVal = CallFunc(Ret32Ty, "helper_fisttl_ST0", CPUEnv);
//         break;
//     case 8:
//         MemVal = CallFunc(Ret64Ty, "helper_fisttll_ST0", CPUEnv);
//         break;
//     default:
//         llvm_unreachable("instruction fist opnd size should (2,4,8) bytes.");
//     }
//     StoreOperand(MemVal, InstHdl.getOpnd(0));
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
// }

void X86Translator::translate_fisttp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fisttp\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "fisttp: need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *NewSt0 = GetFPUTop();

    Value *MemVal = LoadFromFPR(NewSt0, FP64Ty);
    MemVal = Builder.CreateFPToSI(MemVal, Int64Ty);

    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = Builder.CreateTrunc(MemVal, Int32Ty);
        break;
    case 8:;
        break;
    default:
        llvm_unreachable(
            "fisttp: instruction fisttp opnd size should (2,4,8) bytes.");
    }
    StoreOperand(MemVal, InstHdl.getOpnd(0));
    NewSt0 = Builder.CreateAdd(NewSt0, ConstInt(Int32Ty, 1));
    NewSt0 = Builder.CreateAnd(NewSt0, ConstInt(Int32Ty, 7));
    SetFPTag(NewSt0, 1);
    SetFPUTop(NewSt0);
}

// void X86Translator::translate_fist(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);

//     Value *MemVal = nullptr;
//     switch (SrcOpnd.getOpndSize()) {
//     case 2:
//         MemVal = CallFunc(Ty, "helper_fist_ST0", CPUEnv);
//         MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
//         break;
//     case 4:
//         MemVal = CallFunc(Ty, "helper_fistl_ST0", CPUEnv);
//         break;
//     default:
//         llvm_unreachable("instruction fist opnd size should (2,4) bytes.");
//     }
//     StoreOperand(MemVal, InstHdl.getOpnd(0));
// }

void X86Translator::translate_fist(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fist\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "fist: need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *NewSt0 = GetFPUTop();

    Value *MemVal = LoadFromFPR(NewSt0, FP64Ty);

    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(),
            Intrinsic::round, MemVal->getType()),
        MemVal);

    MemVal = Builder.CreateFPToSI(MemVal, Int64Ty);

    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = Builder.CreateTrunc(MemVal, Int32Ty);
        break;

    default:
        llvm_unreachable(
            "fist: instruction fist opnd size should (2,4) bytes.");
    }
    StoreOperand(MemVal, InstHdl.getOpnd(0));
}

// void X86Translator::translate_fistp(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *Ret32Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);
//     FunctionType *Ret64Ty = FunctionType::get(Int64Ty, Int8PtrTy, false);

//     Value *MemVal = nullptr;
//     switch (SrcOpnd.getOpndSize()) {
//     case 2:
//         MemVal = CallFunc(Ret32Ty, "helper_fist_ST0", CPUEnv);
//         MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
//         break;
//     case 4:
//         MemVal = CallFunc(Ret32Ty, "helper_fistl_ST0", CPUEnv);
//         break;
//     case 8:
//         MemVal = CallFunc(Ret64Ty, "helper_fistll_ST0", CPUEnv);
//         break;
//     default:
//         llvm_unreachable("instruction fist opnd size should (2,4,8) bytes.");
//     }
//     StoreOperand(MemVal, InstHdl.getOpnd(0));
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
// }

void X86Translator::translate_fistp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fistp\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "fistp: need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *NewSt0 = GetFPUTop();
    Value *MemVal = LoadFromFPR(NewSt0, FP64Ty);

    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(),
            Intrinsic::round, MemVal->getType()),
        MemVal);

    MemVal = Builder.CreateFPToSI(MemVal, Int64Ty);
    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = Builder.CreateTrunc(MemVal, Int32Ty);
        break;
    case 8:
        break;
    default:
        llvm_unreachable(
            "fistp: instruction fistp opnd size should (2,4,8) bytes.");
    }
    NewSt0 = Builder.CreateAdd(NewSt0, ConstInt(Int32Ty, 1));
    NewSt0 = Builder.CreateAnd(NewSt0, ConstInt(Int32Ty, 7));
    SetFPTag(NewSt0, 1);
    SetFPUTop(NewSt0);
    StoreOperand(MemVal, InstHdl.getOpnd(0));
}

// void X86Translator::translate_fldz(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(FTy, "helper_fpush", {CPUEnv});
//     CallFunc(FTy, "helper_fldz_ST0", {CPUEnv});
// }

void X86Translator::translate_fldz(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fldz\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(FP64Ty, 0), newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fld1(GuestInst *Inst) {
//  X86InstHandler InstHdl(Inst);
//  FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//  CallFunc(FTy, "helper_fpush", {CPUEnv});
//  CallFunc(FTy, "helper_fld1_ST0", {CPUEnv});
//}

void X86Translator::translate_fld1(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fld1\n";
    Value *newtop = GetFPUTop();
    newtop = Builder.CreateSub(newtop, ConstInt(Int32Ty, 1));
    newtop = Builder.CreateAnd(newtop, ConstInt(Int32Ty, 7));
    StoreToFPR(ConstantFP::get(FP64Ty, 1), newtop);
    SetFPTag(newtop, 0);
    SetFPUTop(newtop);
}

// void X86Translator::translate_fld(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

//     FunctionType *FPUSHTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FLDTTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

//     if (SrcOpnd.isMem()) { // fld m32fp/m64fp/m80fp
//         if (SrcOpnd.getOpndSize() == 10) {
//             Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
//             CallFunc(FLDTTy, "helper_fldt_ST0", {CPUEnv, Addr});
//         } else {
//             Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
//             FlushFPRValue("ST0", MemVal, false);
//         }
//     } else {
//         Value *DestFPRID = ConstInt(Int32Ty, (SrcOpnd.GetSTRID() + 1) & 7);

//         CallFunc(FPUSHTy, "helper_fpush", {CPUEnv});
//         CallFunc(FMOVTy, "helper_fmov_ST0_STN", {CPUEnv, DestFPRID});
//     }
// }

void X86Translator::translate_fld(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fld\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    if (SrcOpnd.isMem()) { // fld m32fp/m64fp/m80fp
        Value *MemVal = nullptr;
        if (SrcOpnd.getOpndSize() == 4) {
            MemVal = LoadOperand(InstHdl.getOpnd(0), FP32Ty);
            MemVal = Builder.CreateFPExt(MemVal, FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 8) {
            MemVal = LoadOperand(InstHdl.getOpnd(0), FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 10) {
            Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
            FunctionType *FLDTTy =
                FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);
            CallFunc(FLDTTy, "helper_fldt_ST0_To64", {CPUEnv, Addr});
            return;
        } else {
            llvm_unreachable("fld: unknow bit width\n");
        }
        Value *NewSt0 = GetFPUTop();
        NewSt0 = Builder.CreateSub(NewSt0, ConstInt(Int32Ty, 1));
        NewSt0 = Builder.CreateAnd(NewSt0, ConstInt(Int32Ty, 7));
        StoreToFPR(MemVal, NewSt0);
        SetFPUTop(NewSt0);
        SetFPTag(NewSt0, 0);
        // TODO: merge_exception_flags(env, old_flags)
    } else if (SrcOpnd.isSTR()) { // fld from STR
        Value *NewSt0 = GetFPUTop();
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(NewSt0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        Value *Src = LoadFromFPR(DestFPRID, Int64Ty);
        NewSt0 = Builder.CreateSub(NewSt0, ConstInt(Int32Ty, 1));
        NewSt0 = Builder.CreateAnd(NewSt0, ConstInt(Int32Ty, 7));
        StoreToFPR(Src, NewSt0);
        SetFPUTop(NewSt0);
        SetFPTag(NewSt0, 0);
        // TODO: merge_exception_flags
    } else {
        llvm_unreachable("fld: unhandled Opnd\n");
    }
}

// void X86Translator::translate_fsin(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fsin\n";
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fsin", CPUEnv);
// }

void X86Translator::translate_fsin(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsin\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);

    Value *ABS = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::fabs,
            MemVal->getType()),
        MemVal);

    BasicBlock *LessBB = BasicBlock::Create(Context, "Less", TransFunc, ExitBB);
    BasicBlock *LargBB = BasicBlock::Create(Context, "Larg", TransFunc, ExitBB);
    BasicBlock *EndBB = BasicBlock::Create(Context, "End", TransFunc, ExitBB);
    Value *Cond = Builder.CreateFCmpOLT(
        ABS, ConstantFP::get(FP64Ty, APFloat(9223372036854775808.0)));

    Builder.CreateCondBr(Cond, LessBB, LargBB);

    /*---------------------------------------------*/
    Builder.SetInsertPoint(LessBB);

    Value *TOP = GetFPUTop();
    Value *V = LoadFromFPR(TOP, FP64Ty);

    Value *FpusPtr_1 = GetFpusPtr();
    Value *old_flag_1 = Builder.CreateLoad(Int16Ty, FpusPtr_1);
    Value *C_2_1 = nullptr;

    V = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::sin,
            V->getType()),
        V);

    // set C2 to 0

    C_2_1 = ConstInt(Int16Ty, 0xfbff);
    old_flag_1 = Builder.CreateAnd(old_flag_1, C_2_1);
    Builder.CreateStore(old_flag_1, FpusPtr_1);

    StoreToFPR(V, TOP);

    Builder.CreateBr(EndBB);
    /*---------------------------------------------*/
    Builder.SetInsertPoint(LargBB);

    // set C2 to 1
    Value *FpusPtr = GetFpusPtr();
    Value *old_flag = Builder.CreateLoad(Int16Ty, FpusPtr);
    Value *C_2 = nullptr;
    C_2 = ConstInt(Int16Ty, 0x0400);
    old_flag = Builder.CreateOr(old_flag, C_2);
    Builder.CreateStore(old_flag, FpusPtr);

    Builder.CreateBr(EndBB);

    /*---------------------------------------------*/

    Builder.SetInsertPoint(EndBB);
}

// void X86Translator::translate_fsqrt(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fsqrt\n";
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fsqrt", CPUEnv);
// }

void X86Translator::translate_fsqrt(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsqrt\n";
    Value *top = GetFPUTop();
    Value *MemVal = LoadFromFPR(top, FP64Ty);
    MemVal = Builder.CreateCall(
        Intrinsic::getDeclaration(
            Builder.GetInsertBlock()->getParent()->getParent(), Intrinsic::sqrt,
            MemVal->getType()),
        MemVal);

    StoreToFPR(MemVal, top);
}

// void X86Translator::translate_fst(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1 && "need one Opnd");

//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty},
//     false);

//     if (SrcOpnd.isMem()) {
//         Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(), false);
//         StoreOperand(MemVal, InstHdl.getOpnd(0));
//     } else {
//         Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//         CallFunc(FTy, "helper_fmov_STN_ST0", {CPUEnv, DestFPRID});
//     }
// }

void X86Translator::translate_fst(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fst\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *ST0 = GetFPUTop();
    Value *V = nullptr;

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            llvm_unreachable("fst: Opnd Bitwidth err\n");
        } else if (SrcOpnd.getOpndSize() == 8) {
            V = LoadFromFPR(ST0, Int64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            V = LoadFromFPR(ST0, FP64Ty);
            V = Builder.CreateFPTrunc(V, FP32Ty);
            V = Builder.CreateBitCast(V, Int32Ty);
        }
        StoreOperand(V, SrcOpnd.getOpnd());
    } else if (SrcOpnd.isSTR()) {
        V = LoadFromFPR(ST0, FP64Ty);
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(ST0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        StoreToFPR(V, DestFPRID);
    } else {
        llvm_unreachable("fst: unhandled Opnd\n");
        return;
    }
}

// void X86Translator::translate_fstp(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FSTTTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

//     if (SrcOpnd.isMem()) {
//         if (SrcOpnd.getOpndSize() == 10) {
//             Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
//             CallFunc(FSTTTy, "helper_fstt_ST0", {CPUEnv, Addr});
//         } else {
//             Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(),
//             false); StoreOperand(MemVal, InstHdl.getOpnd(0));
//         }
//     } else {
//         Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//         CallFunc(FMOVTy, "helper_fmov_STN_ST0", {CPUEnv, DestFPRID});
//     }
//     CallFunc(FPOPTy, "helper_fpop", CPUEnv);
// }

void X86Translator::translate_fstp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fstp\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *ST0 = GetFPUTop();
    Value *V = nullptr;

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
            Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
            FunctionType *FSTTTy =
                FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);
            CallFunc(FSTTTy, "helper_fstt_ST0_From64", {CPUEnv, Addr});
            // TODO: merge to cmd may be faster
            CallFunc(FPOPTy, "helper_fpop", CPUEnv);
            return;
        } else if (SrcOpnd.getOpndSize() == 8) {
            V = LoadFromFPR(ST0, Int64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            V = LoadFromFPR(ST0, FP64Ty);
            V = Builder.CreateFPTrunc(V, FP32Ty);
            V = Builder.CreateBitCast(V, Int32Ty);
        } else {
            llvm_unreachable("fstp: Opnd Bitwidth err\n");
        }
        StoreOperand(V, SrcOpnd.getOpnd());
    } else if (SrcOpnd.isSTR()) {
        V = LoadFromFPR(ST0, FP64Ty);
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(ST0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        StoreToFPR(V, DestFPRID);
    } else {
        llvm_unreachable("fstp: unhandled Opnd\n");
        return;
    }
    Value *NewST0 = Builder.CreateAdd(ST0, ConstInt(Int32Ty, 1));
    NewST0 = Builder.CreateAnd(NewST0, ConstInt(Int32Ty, 7));
    SetFPTag(NewST0, 1);
    SetFPUTop(NewST0);
}

void X86Translator::translate_fstpnce(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstpnce\n";
    exit(-1);
}

// void X86Translator::translate_fxch(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty},
//     false);

//     Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FTy, "helper_fxchg_ST0_STN", {CPUEnv, SrcFPRID});
// }

void X86Translator::translate_fxch(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fxch\n";
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "fxch: need one Opnd");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *St0 = GetFPUTop();
    Value *Vst0 = LoadFromFPR(St0, Int64Ty);
    Value *DestSTRID = nullptr;
    if (InstHdl.getOpndNum() > 1) {
        llvm_unreachable("fxch: Opnd should be 0 or 1");
    } else if (InstHdl.getOpndNum() == 0) {
        DestSTRID = ConstInt(Int32Ty, 1);
    } else if (SrcOpnd.isSTR()) {
        DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
    } else {
        llvm_unreachable("\nfxch:is not FPR\n");
    }
    Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
    DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
    Value *V = LoadFromFPR(DestFPRID, Int64Ty);
    StoreToFPR(V, St0);
    StoreToFPR(Vst0, DestFPRID);
}

// void X86Translator::translate_fsubr(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fsubr\n";
//     X86InstHandler InstHdl(Inst);
//     GenFPUHelper(Inst, "fsubr", DEST_IS_ST0);
// }

void X86Translator::translate_fsubr(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsubr\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *St0 = GetFPUTop();

        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        Value *DestSTRID = nullptr;
        if (SrcOpnd.isMem()) {
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
        } else if (SrcOpnd.isSTR()) {
            DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFSub(RHS, LHS);
        StoreToFPR(res, St0);
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *St0 = GetFPUTop();
        Value *RHS = nullptr;
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        Value *LHS = LoadFromFPR(DestFPRID, FP64Ty);
        RHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFSub(RHS, LHS);
        StoreToFPR(res, DestFPRID);
    } else {
        llvm_unreachable("fsubr: unhandled Opnds\n");
    }
}

// void X86Translator::translate_fisubr(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fisubr\n";
//     GenFPUHelper(Inst, "fsubr", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_fisubr(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fisubr\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);

    Value *St0 = GetFPUTop();
    Value *LHS = LoadFromFPR(St0, FP64Ty);

    Value *res = Builder.CreateFSub(RHS, LHS);
    StoreToFPR(res, St0);
}

// void X86Translator::translate_fsubrp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fsubr", SHOULD_POP_ONCE);
// }

void X86Translator::translate_fsubrp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsubrp\n";
    X86InstHandler InstHdl(Inst);
    Value *St0 = GetFPUTop();
    Value *FPi = nullptr;
    Value *LHS = LoadFromFPR(St0, FP64Ty);
    if (InstHdl.getOpndNum() == 0) {
        FPi = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isSTR()) {
            llvm_unreachable("fsubrp: Opnd err\n");
        }
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        FPi = Builder.CreateAdd(St0, DestSTRID);
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    }
    Value *RHS = LoadFromFPR(FPi, FP64Ty);
    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreToFPR(res, FPi);
    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fsub(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fsub", DEST_IS_ST0);
// }

void X86Translator::translate_fsub(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsub\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *St0 = GetFPUTop();
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        Value *DestSTRID = nullptr;
        if (SrcOpnd.isMem()) {
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
        } else if (SrcOpnd.isSTR()) {
            DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFSub(LHS, RHS);
        StoreToFPR(res, St0);
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *St0 = GetFPUTop();
        Value *RHS = nullptr;
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        Value *LHS = LoadFromFPR(DestFPRID, FP64Ty);
        RHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFSub(LHS, RHS);
        StoreToFPR(res, DestFPRID);
    } else {
        llvm_unreachable("fsub: unhandled Opnds\n");
    }
    // TODO: merge_exception_flags
}

// void X86Translator::translate_fisub(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fisub\n";
//     GenFPUHelper(Inst, "fsub", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_fisub(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fisub\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);

    Value *St0 = GetFPUTop();
    Value *LHS = LoadFromFPR(St0, FP64Ty);

    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreToFPR(res, St0);
}

// void X86Translator::translate_fsubp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fsub", SHOULD_POP_ONCE);
// }

void X86Translator::translate_fsubp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fsubp\n";
    X86InstHandler InstHdl(Inst);
    Value *St0 = GetFPUTop();
    Value *FPi = nullptr;
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    if (InstHdl.getOpndNum() == 0) {
        FPi = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isSTR()) {
            llvm_unreachable("fsubp:Opnd err\n");
        }
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        FPi = Builder.CreateAdd(St0, DestSTRID);
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    }
    Value *LHS = LoadFromFPR(FPi, FP64Ty);
    Value *res = Builder.CreateFSub(LHS, RHS);
    StoreToFPR(res, FPi);
    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_ftst(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_ftst\n";
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     CallFunc(UnaryFunTy, "helper_fldz_FT0", CPUEnv);
//     CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
// }

void X86Translator::translate_ftst(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_ftst\n";
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fcom_ST0_zero_64", CPUEnv);
}

// void X86Translator::translate_fucomip(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1);

//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.isReg());

//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *FUCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);

//     FlushGMRValue(X86Config::EFLAG);
//     Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(FUCOMITy, "helper_fucomi_ST0_FT0_cogbt", CPUEnv);
//     CallFunc(FPOPTy, "helper_fpop", CPUEnv);
//     ReloadGMRValue(X86Config::EFLAG);
// }

void X86Translator::translate_fucomip(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fucomip\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 1) {
        llvm_unreachable("fucomip: only handle one Opnd\n");
    }
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateBitCast(MemVal, FP64Ty);

    Value *St0 = GetFPUTop();
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareEFLAG(MemVal, RHS);

    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fucomi(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1);

//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     assert(SrcOpnd.isReg());

//     FunctionType *FMOVTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     FunctionType *FUCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);

//     FlushGMRValue(X86Config::EFLAG);
//     Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
//     CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(FUCOMITy, "helper_fucomi_ST0_FT0_cogbt", CPUEnv);
//     ReloadGMRValue(X86Config::EFLAG);
// }

void X86Translator::translate_fucomi(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fucomi\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 1) {
        llvm_unreachable("fucomi: only handle one Opnd\n");
    }
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateBitCast(MemVal, FP64Ty);
    Value *St0 = GetFPUTop();
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareEFLAG(MemVal, RHS);
}

// void X86Translator::translate_fucompp(GuestInst *Inst) {
//     FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
//     FunctionType *Binary32FunTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     Value *SrcFPRID = ConstInt(Int32Ty, 1);
//     CallFunc(Binary32FunTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
//     CallFunc(UnaryFunTy, "helper_fucom_ST0_FT0", CPUEnv);
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
//     CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
// }

void X86Translator::translate_fucompp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fucompp\n";
    X86InstHandler InstHdl(Inst);
    if (InstHdl.getOpndNum() != 0) {
        llvm_unreachable("fucompp: only handle no Opnd\n");
    }
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *St0 = GetFPUTop();
    Value *St1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St1 = Builder.CreateAnd(St1, ConstInt(Int32Ty, 7));
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    Value *LHS = LoadFromFPR(St1, FP64Ty);
    FP64CompareSW(LHS, RHS);
    SetFPTag(St1, 1);
    St1 = Builder.CreateAdd(St1, ConstInt(Int32Ty, 1));
    St1 = Builder.CreateAnd(St1, ConstInt(Int32Ty, 7));
    SetFPTag(St1, 1);
    SetFPUTop(St1);
}

// void X86Translator::translate_fucomp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fucom", DEST_IS_ST0 | SHOULD_POP_ONCE);
// }

void X86Translator::translate_fucomp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fucomp\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();

    if (InstHdl.getOpndNum() == 0) {
        Value *ST1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        ST1 = Builder.CreateAnd(ST1, ConstInt(Int32Ty, 7));
        LHS = LoadFromFPR(ST1, FP64Ty);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        if (SrcOpnd.getOpndSize() == 8) {
            LHS = Builder.CreateBitCast(MemVal, FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateBitCast(MemVal, FP32Ty);
            LHS = Builder.CreateFPExt(LHS, FP64Ty);
        } else {
            llvm_unreachable("fucomp Opnd Bitwidth err\n");
        }
    } else {
        llvm_unreachable("fucomp Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);
}

// void X86Translator::translate_fucom(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fucom", DEST_IS_ST0);
// }

void X86Translator::translate_fucom(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fucom\n";
    X86InstHandler InstHdl(Inst);
    Value *LHS = nullptr;
    Value *St0 = GetFPUTop();
    if (InstHdl.getOpndNum() == 0) {
        Value *ST1 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        ST1 = Builder.CreateAnd(ST1, ConstInt(Int32Ty, 7));
        LHS = LoadFromFPR(ST1, FP64Ty);
    } else if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));

        if (SrcOpnd.getOpndSize() == 8) {
            LHS = Builder.CreateBitCast(MemVal, FP64Ty);
        } else if (SrcOpnd.getOpndSize() == 4) {
            LHS = Builder.CreateBitCast(MemVal, FP32Ty);
            LHS = Builder.CreateFPExt(LHS, FP64Ty);
        } else {
            llvm_unreachable("fucomp Opnd Bitwidth err\n");
        }
    } else {
        llvm_unreachable("fucomp Opnd num err\n");
    }
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    FP64CompareSW(LHS, RHS);
}

void X86Translator::translate_wait(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_wait\n";
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", CPUEnv);
}

// void X86Translator::translate_fdiv(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fdiv\n";
//     X86InstHandler InstHdl(Inst);
//     GenFPUHelper(Inst, "fdiv", DEST_IS_ST0);
// }

void X86Translator::translate_fdiv(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fdiv\n";
    X86InstHandler InstHdl(Inst);
    Value *RHS = nullptr;
    Value *ST0 = nullptr;
    Value *top = GetFPUTop();
    ST0 = LoadFromFPR(top, FP64Ty);
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
        } else if (SrcOpnd.isSTR()) {
            Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(GetFPUTop(), DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        ST0 = Builder.CreateFDiv(ST0, RHS);
        StoreToFPR(ST0, top);
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *stri = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        top = Builder.CreateAdd(top, stri);
        top = Builder.CreateAnd(top, ConstInt(Int32Ty, 7));
        RHS = LoadFromFPR(top, FP64Ty);
        RHS = Builder.CreateFDiv(RHS, ST0);
        StoreToFPR(RHS, top);
    }
}

// void X86Translator::translate_fidiv(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fidiv\n";
//     GenFPUHelper(Inst, "fdiv", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_fidiv(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fidiv\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *top = GetFPUTop();
    Value *ST0 = LoadFromFPR(top, FP64Ty);
    ST0 = Builder.CreateFDiv(ST0, MemVal);
    StoreToFPR(ST0, top);
}

// void X86Translator::translate_fdivp(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fdivp\n";
//     GenFPUHelper(Inst, "fdiv", SHOULD_POP_ONCE);
// }

void X86Translator::translate_fdivp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fdivp\n";
    X86InstHandler InstHdl(Inst);
    Value *stri = nullptr;

    if (InstHdl.getOpndNum() == 0) {
        stri = ConstInt(Int32Ty, 1);
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        stri = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
    }

    Value *St0 = GetFPUTop();
    Value *ST0 = LoadFromFPR(St0, FP64Ty);

    stri = Builder.CreateAdd(St0, stri);
    stri = Builder.CreateAnd(stri, ConstInt(Int32Ty, 7));
    Value *RHS = LoadFromFPR(stri, FP64Ty);
    RHS = Builder.CreateFDiv(RHS, ST0);
    StoreToFPR(RHS, stri);

    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::GenFCMOVHelper(GuestInst *Inst, std::string LBTIntrinic)
// {
//     X86InstHandler InstHdl(Inst);
//     FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
//     Value *Func = Mod->getOrInsertFunction(LBTIntrinic, FTy);
//     Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

//     BasicBlock *MovBB = BasicBlock::Create(Context, "MovBB", TransFunc,
//     ExitBB); BasicBlock *NotMovBB =
//         BasicBlock::Create(Context, "NotMovBB", TransFunc, ExitBB);

//     SyncAllGMRValue();
//     Builder.CreateCondBr(Cond, MovBB, NotMovBB);

//     Builder.SetInsertPoint(MovBB);
//     FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
//     X86OperandHandler STIOpnd(InstHdl.getOpnd(0));
//     Value *SrcFPRID = ConstInt(Int32Ty, STIOpnd.GetSTRID());
//     CallFunc(FTy, "helper_fmov_ST0_STN", {CPUEnv, SrcFPRID});
//     SyncAllGMRValue();
//     Builder.CreateBr(NotMovBB);

//     Builder.SetInsertPoint(NotMovBB);
// }

void X86Translator::GenFCMOVHelper(GuestInst *Inst, std::string LBTIntrinic) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction(LBTIntrinic, FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    BasicBlock *MovBB = BasicBlock::Create(Context, "MovBB", TransFunc, ExitBB);
    BasicBlock *NotMovBB =
        BasicBlock::Create(Context, "NotMovBB", TransFunc, ExitBB);

    SyncAllGMRValue();
    Builder.CreateCondBr(Cond, MovBB, NotMovBB);

    Builder.SetInsertPoint(MovBB);
    X86OperandHandler STIOpnd(InstHdl.getOpnd(0));
    Value *SrcSTRID = ConstInt(Int32Ty, STIOpnd.GetSTRID());
    // CallFunc(FTy, "helper_fmov_ST0_STN", {CPUEnv, SrcFPRID});
    Value *top = GetFPUTop();
    Value *sti = Builder.CreateAdd(top, SrcSTRID);
    sti = Builder.CreateAnd(sti, ConstInt(Int32Ty, 7));
    Value *Stn = LoadFromFPR(sti, FP64Ty);
    StoreToFPR(Stn, top);

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

// void X86Translator::translate_fmul(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fmul", DEST_IS_ST0);
// }

void X86Translator::translate_fmul(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fmul\n";
    X86InstHandler InstHdl(Inst);

    if (InstHdl.getOpndNum() == 1) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        Value *St0 = GetFPUTop();
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        Value *RHS = nullptr;
        Value *DestSTRID = nullptr;
        if (SrcOpnd.isMem()) {
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
        } else if (SrcOpnd.isSTR()) {
            DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFMul(LHS, RHS);
        StoreToFPR(res, St0);
    } else if (InstHdl.getOpndNum() == 2) {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *St0 = GetFPUTop();
        Value *RHS = nullptr;
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        Value *DestFPRID = Builder.CreateAdd(St0, DestSTRID);
        DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
        RHS = LoadFromFPR(DestFPRID, FP64Ty);
        Value *LHS = LoadFromFPR(St0, FP64Ty);
        Value *res = Builder.CreateFMul(LHS, RHS);
        StoreToFPR(res, DestFPRID);
    } else {
        llvm_unreachable("fmul: unhandled Opnds\n");
    }

    // TODO: merge_exception_flags
}

// void X86Translator::translate_fimul(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fimul\n";
//     GenFPUHelper(Inst, "fmul", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_fimul(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fimul\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    Value *RHS = Builder.CreateSIToFP(MemVal, FP64Ty);

    Value *St0 = GetFPUTop();
    Value *LHS = LoadFromFPR(St0, FP64Ty);

    Value *res = Builder.CreateFMul(LHS, RHS);
    StoreToFPR(res, St0);
}

// void X86Translator::translate_fmulp(GuestInst *Inst) {
//     GenFPUHelper(Inst, "fmul", SHOULD_POP_ONCE);
// }

void X86Translator::translate_fmulp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fmulp\n";
    X86InstHandler InstHdl(Inst);
    Value *St0 = GetFPUTop();
    Value *FPi = nullptr;
    Value *RHS = LoadFromFPR(St0, FP64Ty);
    if (InstHdl.getOpndNum() == 0) {
        FPi = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        if (!SrcOpnd.isSTR()) {
            llvm_unreachable("fmulp:Opnd err\n");
        }
        Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        FPi = Builder.CreateAdd(St0, DestSTRID);
        FPi = Builder.CreateAnd(FPi, ConstInt(Int32Ty, 7));
    }
    Value *LHS = LoadFromFPR(FPi, FP64Ty);
    Value *res = Builder.CreateFMul(LHS, RHS);
    StoreToFPR(res, FPi);
    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}

// void X86Translator::translate_fdivr(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fdivr\n";
//     GenFPUHelper(Inst, "fdivr", DEST_IS_ST0);
// }

void X86Translator::translate_fdivr(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fdivr\n";
    X86InstHandler InstHdl(Inst);
    Value *RHS = nullptr;
    Value *ST0 = nullptr;
    Value *top = GetFPUTop();
    ST0 = LoadFromFPR(top, FP64Ty);
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
        } else if (SrcOpnd.isSTR()) {
            Value *DestSTRID = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
            Value *DestFPRID = Builder.CreateAdd(GetFPUTop(), DestSTRID);
            DestFPRID = Builder.CreateAnd(DestFPRID, ConstInt(Int32Ty, 7));
            RHS = LoadFromFPR(DestFPRID, FP64Ty);
        }
        ST0 = Builder.CreateFDiv(RHS, ST0);
        StoreToFPR(ST0, top);
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(1));
        Value *stri = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
        top = Builder.CreateAdd(top, stri);
        top = Builder.CreateAnd(top, ConstInt(Int32Ty, 7));
        RHS = LoadFromFPR(top, FP64Ty);
        RHS = Builder.CreateFDiv(ST0, RHS);
        StoreToFPR(RHS, top);
    }
}

// void X86Translator::translate_fidivr(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fidivr\n";
//     GenFPUHelper(Inst, "fdivr", DEST_IS_ST0 | MEM_VAL_IS_INT);
// }

void X86Translator::translate_fidivr(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fidivr\n";
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateSIToFP(MemVal, FP64Ty);
    Value *top = GetFPUTop();
    Value *ST0 = LoadFromFPR(top, FP64Ty);
    ST0 = Builder.CreateFDiv(MemVal, ST0);
    StoreToFPR(ST0, top);
}

// void X86Translator::translate_fdivrp(GuestInst *Inst) {
//     // dbgs() << "ENTRY translate_fdivrp\n";
//     GenFPUHelper(Inst, "fdivr", SHOULD_POP_ONCE);
// }

void X86Translator::translate_fdivrp(GuestInst *Inst) {
    // dbgs() << "ENTRY translate_fdivrp\n";
    X86InstHandler InstHdl(Inst);
    Value *stri = nullptr;

    if (InstHdl.getOpndNum() == 0) {
        stri = ConstInt(Int32Ty, 1);
    } else {
        X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
        stri = ConstInt(Int32Ty, SrcOpnd.GetSTRID());
    }

    Value *St0 = GetFPUTop();
    Value *ST0 = LoadFromFPR(St0, FP64Ty);

    stri = Builder.CreateAdd(St0, stri);
    stri = Builder.CreateAnd(stri, ConstInt(Int32Ty, 7));
    Value *RHS = LoadFromFPR(stri, FP64Ty);
    RHS = Builder.CreateFDiv(ST0, RHS);
    StoreToFPR(RHS, stri);

    SetFPTag(St0, 1);
    St0 = Builder.CreateAdd(St0, ConstInt(Int32Ty, 1));
    St0 = Builder.CreateAnd(St0, ConstInt(Int32Ty, 7));
    SetFPUTop(St0);
}
