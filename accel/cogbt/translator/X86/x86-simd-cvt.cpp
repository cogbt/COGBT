#include "x86-translator.h"

void X86Translator::translate_cvtsi2sd(GuestInst *Inst) {
    // Convert Doubleword Integer to Scalar Double-Precision Floating-Point Value
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));

    int IntOpndSize = SrcOpnd.getOpndSize();

    // helper_cvtsi2sd type
    assert(IntOpndSize == 4 || IntOpndSize == 8);
    if (IntOpndSize == 4) {
        // Convert 32 bit integer to float point
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *IntVal = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
        CallFunc(FTy, "helper_cvtsi2sd", {CPUEnv, DestXMMID, IntVal});
    } else {
        assert(IntOpndSize == 8);
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *IntVal = LoadOperand(InstHdl.getOpnd(0));
        CallFunc(FTy, "helper_cvtsq2sd", {CPUEnv, DestXMMID, IntVal});
    }
}

void X86Translator::translate_cvtdq2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtdq2pd\n";
    exit(-1);
}
void X86Translator::translate_cvtdq2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtdq2ps\n";
    exit(-1);
}
void X86Translator::translate_cvtpd2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtpd2dq\n";
    exit(-1);
}
void X86Translator::translate_cvtpd2ps(GuestInst *Inst) {
    /* dbgs() << "Untranslated instruction cvtpd2ps\n"; */
    CreateIllegalInstruction();
}
void X86Translator::translate_cvtps2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtps2dq\n";
    exit(-1);
}
void X86Translator::translate_cvtps2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtps2pd\n";
    exit(-1);
}
void X86Translator::translate_cvtsd2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtsd2si\n";
    exit(-1);
}

void X86Translator::translate_cvtsd2ss(GuestInst *Inst) {
    // cvtsd2ss xmm1, xmm2/m64
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));

    Value *SrcXMMID = nullptr;
    if (Opnd0.isMem()) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(Src0, Int64PtrTy);
        SrcXMMID = ConstInt(Int64Ty, -1);
    } else
        SrcXMMID = ConstInt(Int64Ty, Opnd0.GetXMMID());

    Value *DestXMMID = ConstInt(Int64Ty, Opnd1.GetXMMID());
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
    CallFunc(FTy, "helper_cvtsd2ss", {CPUEnv, DestXMMID, SrcXMMID});
}

void X86Translator::translate_cvtsi2ss(GuestInst *Inst) {
    // cvtsi2ss xmm1, r/m32 | r/m64
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));
    if (Opnd0.getOpndSize() == 4) {
        Value *Src = LoadOperand(InstHdl.getOpnd(0));
        Src = Builder.CreateSExt(Src, Int64Ty); // to fix qemu bug
        Value *DestXMMID = ConstInt(Int64Ty, Opnd1.GetXMMID());
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
        CallFunc(FTy, "helper_cvtsi2ss", {CPUEnv, DestXMMID, Src});
    } else {
        assert(Opnd0.getOpndSize() == 8);
        Value *Src = LoadOperand(InstHdl.getOpnd(0));
        Value *DestXMMID = ConstInt(Int64Ty, Opnd1.GetXMMID());
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
        CallFunc(FTy, "helper_cvtsq2ss", {CPUEnv, DestXMMID, Src});
    }
}

void X86Translator::translate_cvtss2sd(GuestInst *Inst) {
    // cvtss2sd xmm1, xmm2/m32
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));

    Value *SrcXMMID = nullptr;
    if (Opnd0.isMem()) {
        Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(Src0, Int32PtrTy);
        SrcXMMID = ConstInt(Int64Ty, -1);
    } else
        SrcXMMID = ConstInt(Int64Ty, Opnd0.GetXMMID());

    Value *DestXMMID = ConstInt(Int64Ty, Opnd1.GetXMMID());
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
    CallFunc(FTy, "helper_cvtss2sd", {CPUEnv, DestXMMID, SrcXMMID});
}

void X86Translator::translate_cvtss2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtss2si\n";
    exit(-1);
}
void X86Translator::translate_cvttpd2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttpd2dq\n";
    exit(-1);
}
void X86Translator::translate_cvttps2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttps2dq\n";
    exit(-1);
}

void X86Translator::translate_cvttsd2si(GuestInst *Inst) {
    // cvttsd2si xmm/m64, r32/r64
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));

    // prepare src value
    int xmmid = -1;
    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
    } else { // xmm reg
        xmmid = SrcOpnd.GetXMMID();
    }
    Value *SrcXMMID = ConstInt(Int64Ty, xmmid);

    // select helpers to do this convert and get the dest value.
    assert(DestOpnd.getOpndSize() == 4 || DestOpnd.getOpndSize() == 8);
    Value *Dest = nullptr;
    if (DestOpnd.getOpndSize() == 4) {
        // trunc float to int32
        FunctionType *FTy =
            FunctionType::get(Int32Ty, {Int8PtrTy, Int64Ty}, false);
        Dest = CallFunc(FTy, "helper_cvttsd2si", {CPUEnv, SrcXMMID});
    } else {
        FunctionType *FTy =
            FunctionType::get(Int64Ty, {Int8PtrTy, Int64Ty}, false);
        Dest = CallFunc(FTy, "helper_cvttsd2sq", {CPUEnv, SrcXMMID});
    }
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cvttss2si(GuestInst *Inst) {
    // cvttss2si r32/r64, xmm/m32
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));

    // prepare src value
    int xmmid = -1;
    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int32PtrTy);
    } else { // xmm reg
        xmmid = SrcOpnd.GetXMMID();
    }
    Value *SrcXMMID = ConstInt(Int64Ty, xmmid);

    // select helpers to do this convert and get the dest value.
    assert(DestOpnd.getOpndSize() == 4 || DestOpnd.getOpndSize() == 8);
    Value *Dest = nullptr;
    if (DestOpnd.getOpndSize() == 4) {
        FunctionType *FTy =
            FunctionType::get(Int32Ty, {Int8PtrTy, Int64Ty}, false);
        Dest = CallFunc(FTy, "helper_cvttss2si", {CPUEnv, SrcXMMID});
    } else {
        FunctionType *FTy =
            FunctionType::get(Int64Ty, {Int8PtrTy, Int64Ty}, false);
        Dest = CallFunc(FTy, "helper_cvttss2sq", {CPUEnv, SrcXMMID});
    }
    StoreOperand(Dest, InstHdl.getOpnd(1));
}
