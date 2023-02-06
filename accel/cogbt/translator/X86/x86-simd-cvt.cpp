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
    dbgs() << "Untranslated instruction cvtpd2ps\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction cvtsd2ss\n";
    exit(-1);
}
void X86Translator::translate_cvtsi2ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtsi2ss\n";
    exit(-1);
}
void X86Translator::translate_cvtss2sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtss2sd\n";
    exit(-1);
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
        Dest = CallFunc(FTy, "helper_cvttsd2dq", {CPUEnv, SrcXMMID});
    }
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cvttss2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttss2si\n";
    exit(-1);
}
