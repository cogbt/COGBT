#include "x86-translator.h"
#include "emulator.h"

void X86Translator::GenMMXSSEHelper(std::string Name, GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    Value *MemVal = nullptr;
    // helper_Name_xxx function type.
    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem())
        MemVal = LoadOperand(InstHdl.getOpnd(0));
    if (DestOpnd.isXMM()) {
        if (MemVal) {
            FlushXMMT0(MemVal);
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
            CallFunc(FuncTy, Name + "_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        } else {
            Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
            Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
            CallFunc(FuncTy, Name + "_xmm", {CPUEnv, DestXMMID, SrcXMMID});
        }

    } else { // MMX
        if (MemVal) {
            FlushMMXT0(MemVal);
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, SrcOpnd.GetMMXID());
            CallFunc(FuncTy, Name + "_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        } else {
            Value *DestMMXID = ConstInt(Int64Ty, DestOpnd.GetMMXID());
            Value *SrcMMXID = ConstInt(Int64Ty, -1);
            CallFunc(FuncTy, Name + "_mmx", {CPUEnv, DestMMXID, SrcMMXID});
        }
    }
}

void X86Translator::translate_paddb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddb", Inst);
}

void X86Translator::translate_paddw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddw", Inst);
}

void X86Translator::translate_paddd(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddl", Inst);
}

void X86Translator::translate_paddq(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddq", Inst);
}

void X86Translator::translate_psubb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubb", Inst);
}

void X86Translator::translate_psubw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubw", Inst);
}

void X86Translator::translate_psubd(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubl", Inst);
}

void X86Translator::translate_psubq(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubq", Inst);
}

void X86Translator::translate_paddsb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddsb", Inst);
}

void X86Translator::translate_paddsw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddsw", Inst);
}

void X86Translator::translate_paddusb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddusb", Inst);
}

void X86Translator::translate_paddusw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_paddusw", Inst);
}

void X86Translator::translate_psubsb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubsb", Inst);
}

void X86Translator::translate_psubsw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubsw", Inst);
}

void X86Translator::translate_psubusb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubusb", Inst);
}

void X86Translator::translate_psubusw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psubusw", Inst);
}

void X86Translator::translate_pmaxsw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmaxsw", Inst);
}

void X86Translator::translate_pmaxub(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmaxub", Inst);
}

void X86Translator::translate_pminsw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pminsw", Inst);
}

void X86Translator::translate_pminub(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pminub", Inst);
}

void X86Translator::translate_pandn(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pandn", Inst);
}

void X86Translator::translate_pand(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pand", Inst);
}

void X86Translator::translate_por(GuestInst *Inst) {
    GenMMXSSEHelper("helper_por", Inst);
}

void X86Translator::translate_pxor(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pxor", Inst);
}

void X86Translator::translate_pcmpgtb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpgtb", Inst);
}

void X86Translator::translate_pcmpgtd(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpgtl", Inst);
}

void X86Translator::translate_pcmpgtw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpgtw", Inst);
}

void X86Translator::translate_pcmpeqb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpeqb", Inst);
}

void X86Translator::translate_pcmpeqd(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpeql", Inst);
}

void X86Translator::translate_pcmpeqw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pcmpeqw", Inst);
}

void X86Translator::translate_pmullw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmullw", Inst);
}

void X86Translator::translate_pmulhrw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmulhrw", Inst);
}

void X86Translator::translate_pmulhuw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmulhuw", Inst);
}

void X86Translator::translate_pmulhw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmulhw", Inst);
}

void X86Translator::translate_pavgb(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pavgb", Inst);
}

void X86Translator::translate_pavgw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pavgw", Inst);
}

void X86Translator::translate_pmuludq(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmuludq", Inst);
}

void X86Translator::translate_pmaddwd(GuestInst *Inst) {
    GenMMXSSEHelper("helper_pmaddwd", Inst);
}

void X86Translator::translate_psadbw(GuestInst *Inst) {
    GenMMXSSEHelper("helper_psadbw", Inst);
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

void X86Translator::translate_pshufd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Src0 = Builder.CreateZExtOrTrunc(Src0, Int32Ty);

    X86OperandHandler Src1Opnd(InstHdl.getOpnd(1));
    Value *Src1 = nullptr;
    if (Src1Opnd.isMem()) {
        Src1 = LoadOperand(InstHdl.getOpnd(1));
        FlushXMMT0(Src1);
        Src1 = ConstInt(Int64Ty, -1);
    } else {
        Src1 = ConstInt(Int64Ty, Src1Opnd.GetXMMID());
    }

    X86OperandHandler DestOpnd(InstHdl.getOpnd(2));
    Value *Dest = ConstInt(Int64Ty, DestOpnd.GetXMMID());

    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty, Int32Ty}, false);
    CallFunc(FuncTy, "helper_pshufd", {CPUEnv, Dest, Src1, Src0});
}

void X86Translator::translate_pshufhw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pshufhw\n";
    exit(-1);
}
void X86Translator::translate_pshuflw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pshuflw\n";
    exit(-1);
}
void X86Translator::translate_movdqu(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_comiss(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    Value *MemVal = nullptr;
    // helper_comiss type
    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    FlushGMRValue(X86Config::EFLAG);

    if (SrcOpnd.isMem())
        MemVal = LoadOperand(InstHdl.getOpnd(0), Int32Ty);

    if (MemVal) {
        FlushXMMT0(MemVal, Int32PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FuncTy, "helper_comiss", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FuncTy, "helper_comiss", {CPUEnv, DestXMMID, SrcXMMID});
    }
    // reload EFLAG
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_comisd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0)); // xmm or mem64
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1)); // xmm
    Value *MemVal = nullptr;
    // helper_comisd type
    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    FlushGMRValue(X86Config::EFLAG);

    if (SrcOpnd.isMem())
        MemVal = LoadOperand(InstHdl.getOpnd(0), Int64Ty);

    if (MemVal) {
        /* printf("memopnd size is %d bytes\n", Inst->detail->x86.operands[0].size); */
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FuncTy, "helper_comisd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FuncTy, "helper_comisd", {CPUEnv, DestXMMID, SrcXMMID});
    }
    // reload EFLAG
    ReloadGMRValue(X86Config::EFLAG);
}

void X86Translator::translate_mulsd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_mulsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_mulsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_mulsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_mulss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulss\n";
    exit(-1);
}
void X86Translator::translate_mulx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mulx\n";
    exit(-1);
}

void X86Translator::translate_addsd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_mulsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_addsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_addsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_minpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction minpd\n";
    exit(-1);
}
void X86Translator::translate_minps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction minps\n";
    exit(-1);
}

void X86Translator::translate_minsd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_mulsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_minsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_minsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_minss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction minss\n";
    exit(-1);
}

void X86Translator::translate_pinsrw(GuestInst *Inst) {
    // pinsrw mm, r32/m16, imm8 OR pinrw xmm, r32/m16, imm8
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd0(InstHdl.getOpnd(0));
    X86OperandHandler SrcOpnd1(InstHdl.getOpnd(1));
    X86OperandHandler SrcOpnd2(InstHdl.getOpnd(2));
    if (SrcOpnd2.isMMX()) {
        /* llvm_unreachable("Unsupported pinsrw mmx yet"); */
        Value *Src = LoadOperand(InstHdl.getOpnd(1), Int16Ty);
        // Calculate dest addr.
        int RegStartByte = (SrcOpnd0.getIMM() & 3) << 1;
        int RegIdx = SrcOpnd2.GetMMXID();
        Value *Off = ConstInt(Int64Ty, GuestMMXRegOffset(RegIdx, RegStartByte));
        Value *DestAddr = Builder.CreateGEP(Int8Ty, CPUEnv, Off);
        DestAddr = Builder.CreateBitCast(DestAddr, Int16PtrTy);
        // Store Src to Dest
        Builder.CreateStore(Src, DestAddr);
    } else {
        assert(SrcOpnd2.isXMM());
        Value *Src = LoadOperand(InstHdl.getOpnd(1), Int16Ty);
        // Calculate dest addr.
        int RegStartByte = (SrcOpnd0.getIMM() & 7) << 1;
        int RegIdx = SrcOpnd2.GetXMMID();
        Value *Off = ConstInt(Int64Ty, GuestZMMRegOffset(RegIdx, RegStartByte));
        Value *DestAddr = Builder.CreateGEP(Int8Ty, CPUEnv, Off);
        DestAddr = Builder.CreateBitCast(DestAddr, Int16PtrTy);
        // Store Src to Dest
        Builder.CreateStore(Src, DestAddr);
    }
}

void X86Translator::translate_divsd(GuestInst *Inst) {
    // divsd xmm1, xmm2/m64
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_divsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_divsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_divsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_divss(GuestInst *Inst) {
    // divss xmm1, xmm2/m32
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_divss llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int32PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_divss", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_divss", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_subpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subpd\n";
    exit(-1);
}
void X86Translator::translate_subps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subps\n";
    exit(-1);
}

void X86Translator::translate_subsd(GuestInst *Inst) {
    // subsd xmm1, xmm2/m64
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_subsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_subsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_subsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_subss(GuestInst *Inst) {
    // subss xmm1, xmm2/m32
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_subss llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int32PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_subss", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_subss", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_sqrtpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sqrtpd\n";
    exit(-1);
}

void X86Translator::translate_sqrtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sqrtps\n";
    exit(-1);
}

void X86Translator::translate_sqrtsd(GuestInst *Inst) {
    // sqrtsd xmm1, xmm2/m64
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_sqrtsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_sqrtsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_sqrtsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_sqrtss(GuestInst *Inst) {
    // sqrtss xmm1, xmm2/m32
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_sqrtss llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int32PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_sqrtss", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_sqrtss", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_maxpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction maxpd\n";
    exit(-1);
}
void X86Translator::translate_maxps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction maxps\n";
    exit(-1);
}

void X86Translator::translate_maxsd(GuestInst *Inst) {
    // maxsd xmm1, xmm2/m64
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_maxsd llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int64PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_maxsd", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_maxsd", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_maxss(GuestInst *Inst) {
    // maxss xmm1, xmm2/m32
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    // helper_maxss llvm type
    FunctionType *FTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);

    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal, Int32PtrTy);
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, -1); // -1 means src is xmm_t0
        CallFunc(FTy, "helper_maxss", {CPUEnv, DestXMMID, SrcXMMID});
    } else {
        Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
        Value *SrcXMMID = ConstInt(Int64Ty, SrcOpnd.GetXMMID());
        CallFunc(FTy, "helper_maxss", {CPUEnv, DestXMMID, SrcXMMID});
    }
}

void X86Translator::translate_xorpd(GuestInst *Inst) {
    // xorpd xmm1, xmm2/m128
    X86InstHandler InstHdl(Inst);

    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));
    int SrcXMM = -1;
    if (SrcOpnd.isMem()) {
        Value *MemVal = LoadOperand(InstHdl.getOpnd(0));
        FlushXMMT0(MemVal);
    } else {
        SrcXMM = SrcOpnd.GetXMMID();
    }

    FunctionType *FuncTy =
        FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty, Int64Ty}, false);
    Value *SrcXMMID = ConstInt(Int64Ty, SrcXMM);
    Value *DestXMMID = ConstInt(Int64Ty, DestOpnd.GetXMMID());
    CallFunc(FuncTy, "helper_xorpd", {CPUEnv, DestXMMID, SrcXMMID});
}
