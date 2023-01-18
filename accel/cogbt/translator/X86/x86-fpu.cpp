#include "x86-translator.h"

void X86Translator::FlushFPRValue(std::string FPR, Value *FV, bool isInt) {
    FunctionType *FuncTy = nullptr;
    int FVBitWidth = FV->getType()->getIntegerBitWidth();
    if (FVBitWidth == 16) {
        FV = Builder.CreateSExt(FV, Int32Ty);
        FuncTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        assert(!isInt && "Can't treat 16bit value as float\n");
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
    bool MemValisInteger = Flags &  MEM_VAL_IS_INT;
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
                Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
                CallFunc(FTy2, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
                CallFunc(FTy, "helper_" + Name + "_ST0_FT0", CPUEnv);
            } else {
                // DestOpnd is SrcOpnd and another SrcOpnd is st(0) like faddp
                Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
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
    }
    else { // e.g fsub st0, sti means st(i) - st(0) -> st(i)
        FunctionType *FTy2 =
            FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
        Value *DestFPRID = ConstInt(Int32Ty, DestOpnd.GetFPRID());
        assert(DestFPRID);
        CallFunc(FTy2, "helper_" + Name + "_STN_ST0", {CPUEnv, DestFPRID});
    }
}

void X86Translator::translate_fabs(GuestInst *Inst) {
    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FuncTy, "helper_fabs_ST0", CPUEnv);
}

void X86Translator::translate_fadd(GuestInst *Inst) {
    GenFPUHelper(Inst, "fadd", DEST_IS_ST0);
}

void X86Translator::translate_fiadd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 &&
           "fiadd does not support opnd number!\n");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem() && "fiadd opnd must mem!\n");
    GenFPUHelper(Inst, "fadd", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_faddp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "faddp does not support opnd number\n");
    GenFPUHelper(Inst, "fadd", SHOULD_POP_ONCE);
}

void X86Translator::translate_fchs(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fchs_ST0", {CPUEnv});
}

void X86Translator::translate_fcomp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | SHOULD_POP_ONCE);
}

void X86Translator::translate_fcompp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | SHOULD_POP_TWICE);
}

void X86Translator::translate_fcomip(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg() && "operand of fcomip must be fpr");
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FCOMITy = FunctionType::get(Int32Ty, Int8PtrTy, false);
    FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    CallFunc(FPOPTy, "helper_fpop", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fcomi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg() && "operand of fcomi must be fpr");
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FCOMITy = FunctionType::get(Int32Ty, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fcom(GuestInst *Inst) {
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0);
}

void X86Translator::translate_fcos(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fcos", CPUEnv);
}

void X86Translator::translate_f2xm1(GuestInst *Inst) {
    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FuncTy, "helper_f2xm1", {CPUEnv});
}

void X86Translator::translate_fbld(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem());
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    CallFunc(FTy, "helper_fbld_ST0", {CPUEnv, Addr});
}

void X86Translator::translate_fbstp(GuestInst *Inst) {
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

void X86Translator::translate_fdecstp(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fdecstp", CPUEnv);
}

void X86Translator::translate_femms(GuestInst *Inst) {
    dbgs() << "Untranslated instruction femms\n";
    exit(-1);
}

void X86Translator::translate_ffree(GuestInst *Inst) {
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

void X86Translator::translate_fincstp(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fincstp", CPUEnv);
}

void X86Translator::translate_fldcw(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    MemVal = Builder.CreateZExt(MemVal, Int32Ty);
    CallFunc(FTy, "helper_fldcw", {CPUEnv, MemVal});
}

void X86Translator::translate_fldenv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fldenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fldl2e(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldl2e_ST0", {CPUEnv});
}

void X86Translator::translate_fldl2t(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldl2t_ST0", {CPUEnv});
}

void X86Translator::translate_fldlg2(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldlg2_ST0", {CPUEnv});
}

void X86Translator::translate_fldln2(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldln2_ST0", {CPUEnv});
}

void X86Translator::translate_fldpi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldpi_ST0", {CPUEnv});
}

void X86Translator::translate_fnclex(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fclex", CPUEnv);
}

void X86Translator::translate_fninit(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fninit", CPUEnv);
}

void X86Translator::translate_fnop(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", {CPUEnv});
}

void X86Translator::translate_fnstcw(GuestInst *Inst) {
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
        dbgs() << "fnstsw does not support opnd type\n";
        exit(-1);
    }
}

void X86Translator::translate_fpatan(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpatan", CPUEnv);
}

void X86Translator::translate_fprem(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem", CPUEnv);
}

void X86Translator::translate_fprem1(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem1", CPUEnv);
}

void X86Translator::translate_fptan(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fptan", CPUEnv);
}

void X86Translator::translate_ffreep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffreep\n";
    exit(-1);
}

void X86Translator::translate_frndint(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_frndint", CPUEnv);
}

void X86Translator::translate_frstor(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_frstor", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fnsave(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fsave", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fscale(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fscale", CPUEnv);
}

void X86Translator::translate_fsetpm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsetpm\n";
    exit(-1);
}

void X86Translator::translate_fsincos(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fsincos", CPUEnv);
}

void X86Translator::translate_fnstenv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
    FunctionType *Ty =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int32Ty}, false);
    CallFunc(Ty, "helper_fstenv", {CPUEnv, Addr, ConstInt(Int32Ty, 1)});
}

void X86Translator::translate_fxam(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxam", CPUEnv);
}

void X86Translator::translate_fxtract(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxtract", CPUEnv);
}

void X86Translator::translate_fyl2x(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fyl2x", CPUEnv);
}

void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fyl2xp1", CPUEnv);
}

void X86Translator::translate_fild(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(InstHdl.getOpndNum() == 1 && SrcOpnd.isMem());
    Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
    FlushFPRValue("ST0", MemVal, true);
}

void X86Translator::translate_fisttp(GuestInst *Inst) {
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
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);

    Value *MemVal = nullptr;
    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = CallFunc(Ty, "helper_fist_ST0", CPUEnv);
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = CallFunc(Ty, "helper_fistl_ST0", CPUEnv);
        break;
    default:
        llvm_unreachable("instruction fist opnd size should (2,4) bytes.");
    }
    StoreOperand(MemVal, InstHdl.getOpnd(0));
}

void X86Translator::translate_fistp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *Ret32Ty = FunctionType::get(Int32Ty, Int8PtrTy, false);
    FunctionType *Ret64Ty = FunctionType::get(Int64Ty, Int8PtrTy, false);

    Value *MemVal = nullptr;
    switch (SrcOpnd.getOpndSize()) {
    case 2:
        MemVal = CallFunc(Ret32Ty, "helper_fist_ST0", CPUEnv);
        MemVal = Builder.CreateTrunc(MemVal, Int16Ty);
        break;
    case 4:
        MemVal = CallFunc(Ret32Ty, "helper_fistl_ST0", CPUEnv);
        break;
    case 8:
        MemVal = CallFunc(Ret64Ty, "helper_fistll_ST0", CPUEnv);
        break;
    default:
        llvm_unreachable("instruction fist opnd size should (2,4,8) bytes.");
    }
    StoreOperand(MemVal, InstHdl.getOpnd(0));
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fldz(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldz_ST0", {CPUEnv});
}

void X86Translator::translate_fld1(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fld1_ST0", {CPUEnv});
}

void X86Translator::translate_fld(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

    FunctionType *FPUSHTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FLDTTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
            CallFunc(FLDTTy, "helper_fldt_ST0", {CPUEnv, Addr});
        } else {
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            FlushFPRValue("ST0", MemVal, false);
        }
    } else {
        Value *DestFPRID = ConstInt(Int32Ty, (SrcOpnd.GetFPRID() + 1) & 7);
        CallFunc(FPUSHTy, "helper_fpush", {CPUEnv});
        CallFunc(FMOVTy, "helper_fmov_ST0_STN", {CPUEnv, DestFPRID});
    }
}

void X86Translator::translate_fsin(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fsin", CPUEnv);
}

void X86Translator::translate_fsqrt(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fsqrt", CPUEnv);
}

void X86Translator::translate_fst(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(), false);
        StoreOperand(MemVal, InstHdl.getOpnd(0));
    } else {
        Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
        CallFunc(FTy, "helper_fmov_STN_ST0", {CPUEnv, DestFPRID});
    }
}

void X86Translator::translate_fstp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FSTTTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
            CallFunc(FSTTTy, "helper_fstt_ST0", {CPUEnv, Addr});
        } else {
            Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(), false);
            StoreOperand(MemVal, InstHdl.getOpnd(0));
        }
    } else {
        Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
        CallFunc(FMOVTy, "helper_fmov_STN_ST0", {CPUEnv, DestFPRID});
    }
    CallFunc(FPOPTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fstpnce(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstpnce\n";
    exit(-1);
}

void X86Translator::translate_fxch(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FTy, "helper_fxchg_ST0_STN", {CPUEnv, SrcFPRID});
}

void X86Translator::translate_fsubr(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    GenFPUHelper(Inst, "fsubr", DEST_IS_ST0);
}

void X86Translator::translate_fisubr(GuestInst *Inst) {
    GenFPUHelper(Inst, "fsubr", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fsubrp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fsubr", SHOULD_POP_ONCE);
}

void X86Translator::translate_fsub(GuestInst *Inst) {
    GenFPUHelper(Inst, "fsub", DEST_IS_ST0);
}

void X86Translator::translate_fisub(GuestInst *Inst) {
    GenFPUHelper(Inst, "fsub", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fsubp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fsub", SHOULD_POP_ONCE);
}

void X86Translator::translate_ftst(GuestInst *Inst) {
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fldz_FT0", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
}

void X86Translator::translate_fucomip(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg());

    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *FUCOMITy = FunctionType::get(Int32Ty, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FUCOMITy, "helper_fucomi_ST0_FT0_cogbt", CPUEnv);
    CallFunc(FPOPTy, "helper_fpop", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fucomi(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg());

    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FUCOMITy = FunctionType::get(Int32Ty, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FUCOMITy, "helper_fucomi_ST0_FT0_cogbt", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fucompp(GuestInst *Inst) {
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
    GenFPUHelper(Inst, "fucom", DEST_IS_ST0 | SHOULD_POP_ONCE);
}

void X86Translator::translate_fucom(GuestInst *Inst) {
    GenFPUHelper(Inst, "fucom", DEST_IS_ST0);
}

void X86Translator::translate_wait(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", CPUEnv);
}

void X86Translator::translate_fdiv(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    GenFPUHelper(Inst, "fdiv", DEST_IS_ST0);
}

void X86Translator::translate_fidiv(GuestInst *Inst) {
    GenFPUHelper(Inst, "fdiv", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fdivp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fdiv", SHOULD_POP_ONCE);
}

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
    FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    X86OperandHandler STIOpnd(InstHdl.getOpnd(0));
    Value *SrcFPRID = ConstInt(Int32Ty, STIOpnd.GetFPRID());
    CallFunc(FTy, "helper_fmov_ST0_STN", {CPUEnv, SrcFPRID});
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
    GenFPUHelper(Inst, "fmul", DEST_IS_ST0);
}

void X86Translator::translate_fimul(GuestInst *Inst) {
    GenFPUHelper(Inst, "fmul", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fmulp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fmul", SHOULD_POP_ONCE);
}

void X86Translator::translate_fdivr(GuestInst *Inst) {
    GenFPUHelper(Inst, "fdivr", DEST_IS_ST0);
}

void X86Translator::translate_fidivr(GuestInst *Inst) {
    GenFPUHelper(Inst, "fdivr", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fdivrp(GuestInst *Inst) {
    GenFPUHelper(Inst, "fdivr", SHOULD_POP_ONCE);
}
