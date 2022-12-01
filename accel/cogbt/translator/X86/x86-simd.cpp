#include "x86-translator.h"

void X86Translator::translate_pxor(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    Value *MemVal = nullptr;
    // helper_pxor_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem())
        MemVal = LoadOperand(InstHdl.getOpnd(0));
    if (DestOpnd.isXMM()) {
        if (MemVal) {
            FlushXMMT0(MemVal);
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
            CallFunc(FuncTy, "helper_pxor_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        } else {
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_pxor_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        }

    } else { // MMX
        if (MemVal) {
            FlushMMXT0(MemVal);
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_pxor_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        } else {
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, -1);
            CallFunc(FuncTy, "helper_pxor_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        }
    }
}

void X86Translator::translate_movdqu(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_pcmpeqb(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    Value *MemVal = nullptr;
    // helper_pcmpeqb_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem())
        MemVal = LoadOperand(InstHdl.getOpnd(0));
    if (DestOpnd.isXMM()) {
        if (MemVal) {
            FlushXMMT0(MemVal);
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
            CallFunc(FuncTy, "helper_pcmpeqb_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        } else {
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_pcmpeqb_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        }

    } else { // MMX
        if (MemVal) {
            FlushMMXT0(MemVal);
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_pcmpeqb_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        } else {
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, -1);
            CallFunc(FuncTy, "helper_pcmpeqb_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        }
    }
}

void X86Translator::translate_pcmpeqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpeqd\n";
    exit(-1);
}
void X86Translator::translate_pcmpeqw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpeqw\n";
    exit(-1);
}

void X86Translator::translate_pmovmskb(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // helper_pmovmskb_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(Int32Ty, {Int8PtrTy, Int64Ty}, false);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    Value *Dest = nullptr;
    if (SrcOpnd.isXMM()) {
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        Dest = CallFunc(FuncTy, "helper_pmovmskb_xmm", {CPUEnv, SrcXMMID});
    } else { //MMX
        Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
        Dest = CallFunc(FuncTy, "helper_pmovmskb_mmx", {CPUEnv, SrcMMXID});
    }
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_punpckhbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpckhbw\n";
    exit(-1);
}
void X86Translator::translate_punpckhdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpckhdq\n";
    exit(-1);
}
void X86Translator::translate_punpckhwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpckhwd\n";
    exit(-1);
}
void X86Translator::translate_punpcklbw(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // helper_punpcklvw_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(Int32Ty, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    if (SrcOpnd.isMem()) {
        Value *MemV = LoadOperand(InstHdl.getOpnd(0));
        if (DestOpnd.isMMX()) {
            FlushMMXT0(MemV);
            Value *MMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_punpcklbw_mmx",
                     {CPUEnv, MMXID, ConstInt(Int64Ty, -1)});
        } else {
            assert(DestOpnd.isXMM());
            FlushXMMT0(MemV);
            Value *XMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_punpcklbw_xmm",
                     {XMMID, ConstInt(Int64Ty, -1)});
        }
    } else { // both xmm or mmx.
        if (SrcOpnd.isMMX()) {
            Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_punpcklbw_mmx",
                     {CPUEnv, DestMMXID, SrcMMXID});
        } else {
            assert(DestOpnd.isXMM());
            Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_punpcklbw_xmm",
                     {CPUEnv, DestXMMID, SrcXMMID});
        }
    }
}

void X86Translator::translate_punpckldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpckldq\n";
    exit(-1);
}
void X86Translator::translate_punpcklwd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // helper_punpcklvw_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(Int32Ty, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    if (SrcOpnd.isMem()) {
        Value *MemV = LoadOperand(InstHdl.getOpnd(0));
        if (DestOpnd.isMMX()) {
            FlushMMXT0(MemV);
            Value *MMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_punpcklwd_mmx",
                     {CPUEnv, MMXID, ConstInt(Int64Ty, -1)});
        } else {
            assert(DestOpnd.isXMM());
            FlushXMMT0(MemV);
            Value *XMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_punpcklwd_xmm",
                     {XMMID, ConstInt(Int64Ty, -1)});
        }
    } else { // both xmm or mmx.
        if (SrcOpnd.isMMX()) {
            Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            CallFunc(FuncTy, "helper_punpcklwd_mmx",
                     {CPUEnv, DestMMXID, SrcMMXID});
        } else {
            assert(DestOpnd.isXMM());
            Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            CallFunc(FuncTy, "helper_punpcklwd_xmm",
                     {CPUEnv, DestXMMID, SrcXMMID});
        }
    }
}
