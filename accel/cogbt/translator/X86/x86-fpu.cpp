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
    FV = Builder.CreateBitCast(FV, Int64Ty);
    FunctionType *FuncTy = nullptr;
    // int FVBitWidth = FV->getType()->getIntegerBitWidth();
    int FVBitWidth = 64;
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

        if (ShouldPopOnce) {
            CallFunc(FTy, "helper_fpop", CPUEnv);
        }
        if (ShouldPopTwice) {
            CallFunc(FTy, "helper_fpop", CPUEnv);
            CallFunc(FTy, "helper_fpop", CPUEnv);
        }
    } else { // e.g fsub st0, sti means st(i) - st(0) -> st(i)
        FunctionType *FTy2 =
            FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
        X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
        Value *DestFPRID = ConstInt(Int32Ty, DestOpnd.GetFPRID());
        assert(DestFPRID);
        CallFunc(FTy2, "helper_" + Name + "_STN_ST0", {CPUEnv, DestFPRID});
    }
}

void X86Translator::translate_fabs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fabs\n";
    exit(-1);
    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FuncTy, "helper_fabs_ST0", CPUEnv);
}
void X86Translator::translate_fadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fadd\n";
    exit(-1);
    GenFPUHelper(Inst, "fadd", DEST_IS_ST0);
}
// void X86Translator::translate_fadd(GuestInst *Inst) {
//     /* GenFPUHelper(Inst, "fadd", DEST_IS_ST0); */
//     X86InstHandler InstHdl(Inst);
//     assert(InstHdl.getOpndNum() == 1 || InstHdl.getOpndNum() == 2);

//     if (InstHdl.getOpndNum() == 1) {
//         X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));

//         if (SrcOpnd.isMem()) { // e.g fadd m32fp / m64fp
//             int op_size = SrcOpnd.getOpndSize();
//             assert(op_size == 4 || op_size == 8);
//             Value *MemVal = LoadOperand(InstHdl.getOpnd(0),
//                                         (op_size == 4) ? FP32Ty : FP64Ty);
//             StoreGMRValue(MemVal, X87GetCurrST0());
//         } else {
//             assert(SrcOpnd.isReg());
//             // DestOpnd is st(0) e.g fsub st(1) means st(0) - st(1) -> st(0)
//             Value *STI = LoadOperand(InstHdl.getOpnd(0), FP64Ty);
//             Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
//             ST0 = Builder.CreateFAdd(STI, ST0);
//             StoreGMRValue(ST0, X87GetCurrST0());
//         }
//     } else { // e.g fsub st0, sti means st(i) - st(0) -> st(i)
//         Value *STI = LoadOperand(InstHdl.getOpnd(0), FP64Ty);
//         Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
//         STI = Builder.CreateFAdd(STI, ST0);
//         StoreOperand(STI, InstHdl.getOpnd(0));
//     }
// }

void X86Translator::translate_fiadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fiadd\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 &&
           "fiadd does not support opnd number!\n");
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isMem() && "fiadd opnd must mem!\n");
    GenFPUHelper(Inst, "fadd", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_faddp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction faddp\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1 && "faddp does not support opnd number\n");
    GenFPUHelper(Inst, "fadd", SHOULD_POP_ONCE);
}

void X86Translator::translate_fchs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fchs\n";
    exit(-1);

    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fchs_ST0", {CPUEnv});
}

void X86Translator::translate_fcomp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomp\n";
    exit(-1);

    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | SHOULD_POP_ONCE);
}

void X86Translator::translate_fcompp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcompp\n";
    exit(-1);

    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *Binary32FunTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    Value *SrcFPRID = ConstInt(Int32Ty, 1);
    CallFunc(Binary32FunTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(UnaryFunTy, "helper_fcom_ST0_FT0", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
    CallFunc(UnaryFunTy, "helper_fpop", CPUEnv);
}

void X86Translator::translate_fcomip(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomip\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg() && "operand of fcomip must be fpr");
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);
    FunctionType *FPOPTy = FunctionType::get(VoidTy, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    CallFunc(FPOPTy, "helper_fpop", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fcomi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomi\n";
    exit(-1);
    X86InstHandler InstHdl(Inst);
    assert(InstHdl.getOpndNum() == 1);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    assert(SrcOpnd.isReg() && "operand of fcomi must be fpr");
    FunctionType *FMOVTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);
    FunctionType *FCOMITy = FunctionType::get(VoidTy, Int8PtrTy, false);

    FlushGMRValue(X86Config::EFLAG);
    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FMOVTy, "helper_fmov_FT0_STN", {CPUEnv, SrcFPRID});
    CallFunc(FCOMITy, "helper_fcomi_ST0_FT0_cogbt", CPUEnv);
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_fcom(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcom\n";
    exit(-1);
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0);
}

void X86Translator::translate_fcos(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcos\n";
    exit(-1);

    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fcos", CPUEnv);
}

void X86Translator::translate_f2xm1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction f2xm1\n";
    exit(-1);
    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FuncTy, "helper_f2xm1", {CPUEnv});
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
    dbgs() << "Untranslated instruction ficom\n";
    exit(-1);
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_ficomp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ficomp\n";
    exit(-1);
    GenFPUHelper(Inst, "fcom", DEST_IS_ST0 | MEM_VAL_IS_INT | SHOULD_POP_ONCE);
}

void X86Translator::translate_fincstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fincstp\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fincstp", CPUEnv);
    // X87FPR_Pop();
}

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
    dbgs() << "Untranslated instruction fldl2t\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldl2t_ST0", {CPUEnv});
}

void X86Translator::translate_fldlg2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldlg2\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldlg2_ST0", {CPUEnv});
}

void X86Translator::translate_fldln2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldln2\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldln2_ST0", {CPUEnv});
}

void X86Translator::translate_fldpi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldpi\n";
    exit(-1);

    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fldpi_ST0", {CPUEnv});
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
    dbgs() << "Untranslated instruction fnstsw\n";
    exit(-1);

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
    dbgs() << "Untranslated instruction fpatan\n";
    exit(-1);

    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpatan", CPUEnv);
}

void X86Translator::translate_fprem(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fprem\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem", CPUEnv);
}

void X86Translator::translate_fprem1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fprem1\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fprem1", CPUEnv);
}

void X86Translator::translate_fptan(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fptan\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fptan", CPUEnv);
}

void X86Translator::translate_ffreep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffreep\n";
    exit(-1);
}

void X86Translator::translate_frndint(GuestInst *Inst) {
    dbgs() << "Untranslated instruction frndint\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_frndint", CPUEnv);
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
    dbgs() << "Untranslated instruction fscale\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fscale", CPUEnv);
}

void X86Translator::translate_fsetpm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsetpm\n";
    exit(-1);
}

void X86Translator::translate_fsincos(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsincos\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fsincos", CPUEnv);
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
    dbgs() << "Untranslated instruction fxtract\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fxtract", CPUEnv);
}

void X86Translator::translate_fyl2x(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fyl2x\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fyl2x", CPUEnv);
}

void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fyl2xp1\n";
    exit(-1);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fyl2xp1", CPUEnv);
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
    dbgs() << "Untranslated instruction fist\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction fistp\n";
    exit(-1);
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
    X87FPR_Push();
    StoreGMRValue(ConstantFP::get(Context, APFloat(0.0)), X87GetCurrST0());
}

void X86Translator::translate_fld1(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fld1\n");
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fpush", {CPUEnv});
    CallFunc(FTy, "helper_fld1_ST0", {CPUEnv});
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
            // X87FPR_Push();
            // Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            // StoreGMRValue(MemVal, X87GetCurrST0());
        } else {
            X87FPR_Push();
            // Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            // FlushFPRValue("ST0", MemVal, false);
            Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
            StoreGMRValue(MemVal, X87GetCurrST0());
        }
    } else {
        // assert(0 && "it is developing");
        // Value *DestFPRID = ConstInt(Int32Ty, (SrcOpnd.GetFPRID() + 1) & 7);
        // CallFunc(FPUSHTy, "helper_fpush", {CPUEnv});
        // CallFunc(FMOVTy, "helper_fmov_ST0_STN", {CPUEnv, DestFPRID});

        Value *STI = LoadOperand(InstHdl.getOpnd(0), FP64Ty);
        X87FPR_Push();
        StoreGMRValue(STI, X87GetCurrST0());
    }
}

void X86Translator::translate_fsin(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fsin\n");
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fsin", CPUEnv);
}

void X86Translator::translate_fsqrt(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fsqrt\n");
    FunctionType *UnaryFunTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(UnaryFunTy, "helper_fsqrt", CPUEnv);
}

void X86Translator::translate_fst(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    // FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty},
    // false);

    if (SrcOpnd.isMem()) {
        // Value *MemVal = ReloadFPRValue("ST0", SrcOpnd.getOpndSize(), false);
        StoreOperand(LoadGMRValue(FP64Ty, X87GetCurrSTI(0)),
                     InstHdl.getOpnd(0));
    } else {
        assert(0 && "it is developing");
        // Value *DestFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
        // CallFunc(FTy, "helper_fmov_STN_ST0", {CPUEnv, DestFPRID});
    }
}

// void X86Translator::translate_fstp(GuestInst *Inst) {
//     X86InstHandler InstHdl(Inst);
//     X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
//     FunctionType *FSTTTy =
//         FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

//     if (SrcOpnd.isMem()) {
//         if (SrcOpnd.getOpndSize() == 10) {
//             assert(0 && "it is developing");
//             Value *Addr = CalcMemAddr(InstHdl.getOpnd(0));
//             CallFunc(FSTTTy, "helper_fstt_ST0", {CPUEnv, Addr});
//         } else if (SrcOpnd.getOpndSize() == 32) {
//             Value *ST0 = LoadGMRValue(FP32Ty, X87GetCurrST0());
//             StoreOperand(ST0, InstHdl.getOpnd(0));
//         } else if (SrcOpnd.getOpndSize() == 64) {
//             Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
//             StoreOperand(ST0, InstHdl.getOpnd(0));
//         }
//     } else {
//         Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
//         StoreOperand(ST0, InstHdl.getOpnd(0));
//     }
//     X87FPR_Pop();
// }

void X86Translator::translate_fstp(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    // FunctionType *FSTTTy =
    //     FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        if (SrcOpnd.getOpndSize() == 10) {
            assert(0 && "it is developing");
            // Value *ST0 = LoadGMRValue(FP64Ty, X87GetCurrST0());
            // StoreOperand(ST0, InstHdl.getOpnd(0));
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
    X87FPR_Pop();
}

void X86Translator::translate_fstpnce(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstpnce\n";
    exit(-1);
}

void X86Translator::translate_fxch(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fxch\n");
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int32Ty}, false);

    Value *SrcFPRID = ConstInt(Int32Ty, SrcOpnd.GetFPRID());
    CallFunc(FTy, "helper_fxchg_ST0_STN", {CPUEnv, SrcFPRID});
}

void X86Translator::translate_fsubr(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fsubr\n");
    X86InstHandler InstHdl(Inst);
    GenFPUHelper(Inst, "fsubr", DEST_IS_ST0);
}

void X86Translator::translate_fisubr(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fisubr\n");
    GenFPUHelper(Inst, "fsubr", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fsubrp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fsubrp\n");
    GenFPUHelper(Inst, "fsubr", SHOULD_POP_ONCE);
}

void X86Translator::translate_fsub(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fsub\n");
    GenFPUHelper(Inst, "fsub", DEST_IS_ST0);
}

void X86Translator::translate_fisub(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fisub\n");
    GenFPUHelper(Inst, "fsub", DEST_IS_ST0 | MEM_VAL_IS_INT);
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
    assert(0 && "Untranslated instruction wait\n");
    FunctionType *FTy = FunctionType::get(VoidTy, Int8PtrTy, false);
    CallFunc(FTy, "helper_fwait", CPUEnv);
}

void X86Translator::translate_fdiv(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fdiv\n");
    X86InstHandler InstHdl(Inst);
    GenFPUHelper(Inst, "fdiv", DEST_IS_ST0);
}

void X86Translator::translate_fidiv(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fidiv\n");
    GenFPUHelper(Inst, "fdiv", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fdivp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fdivp\n");
    GenFPUHelper(Inst, "fdiv", SHOULD_POP_ONCE);
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
    Value *SrcFPRID = ConstInt(Int32Ty, STIOpnd.GetFPRID());
    CallFunc(FTy, "helper_fmov_ST0_STN", {CPUEnv, SrcFPRID});
    SyncAllGMRValue();
    Builder.CreateBr(NotMovBB);

    Builder.SetInsertPoint(NotMovBB);
}

void X86Translator::translate_fcmovbe(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovbe\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjbe");
}

void X86Translator::translate_fcmovb(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovb\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjb");
}

void X86Translator::translate_fcmove(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmove\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setje");
}

void X86Translator::translate_fcmovnbe(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovnbe\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setja");
}

void X86Translator::translate_fcmovnb(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovnb\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjae");
}

void X86Translator::translate_fcmovne(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovne\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjne");
}

void X86Translator::translate_fcmovnu(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovnu\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjnp");
}

void X86Translator::translate_fcmovu(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fcmovu\n");
    GenFCMOVHelper(Inst, "llvm.loongarch.x86setjp");
}

void X86Translator::translate_fmul(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fmul\n");
    GenFPUHelper(Inst, "fmul", DEST_IS_ST0);
}

void X86Translator::translate_fimul(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fimul\n");
    GenFPUHelper(Inst, "fmul", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fmulp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fmulp\n");
    GenFPUHelper(Inst, "fmul", SHOULD_POP_ONCE);
}

void X86Translator::translate_fdivr(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fdivr\n");
    GenFPUHelper(Inst, "fdivr", DEST_IS_ST0);
}

void X86Translator::translate_fidivr(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fidivr\n");
    GenFPUHelper(Inst, "fdivr", DEST_IS_ST0 | MEM_VAL_IS_INT);
}

void X86Translator::translate_fdivrp(GuestInst *Inst) {
    assert(0 && "Untranslated instruction fdivrp\n");
    GenFPUHelper(Inst, "fdivr", SHOULD_POP_ONCE);
}
