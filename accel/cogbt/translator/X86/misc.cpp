#include "emulator.h"
#include "x86-translator.h"

void X86Translator::translate_fabs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fabs\n";
    exit(-1);
}
void X86Translator::translate_addpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addpd\n";
    exit(-1);
}
void X86Translator::translate_addps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addps\n";
    exit(-1);
}
void X86Translator::translate_addsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addsd\n";
    exit(-1);
}
void X86Translator::translate_addss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addss\n";
    exit(-1);
}
void X86Translator::translate_addsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addsubpd\n";
    exit(-1);
}
void X86Translator::translate_addsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction addsubps\n";
    exit(-1);
}
void X86Translator::translate_fadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fadd\n";
    exit(-1);
}
void X86Translator::translate_fiadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fiadd\n";
    exit(-1);
}
void X86Translator::translate_faddp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction faddp\n";
    exit(-1);
}
void X86Translator::translate_adox(GuestInst *Inst) {
    dbgs() << "Untranslated instruction adox\n";
    exit(-1);
}
void X86Translator::translate_aesdeclast(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aesdeclast\n";
    exit(-1);
}
void X86Translator::translate_aesdec(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aesdec\n";
    exit(-1);
}
void X86Translator::translate_aesenclast(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aesenclast\n";
    exit(-1);
}
void X86Translator::translate_aesenc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aesenc\n";
    exit(-1);
}
void X86Translator::translate_aesimc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aesimc\n";
    exit(-1);
}
void X86Translator::translate_aeskeygenassist(GuestInst *Inst) {
    dbgs() << "Untranslated instruction aeskeygenassist\n";
    exit(-1);
}
void X86Translator::translate_andn(GuestInst *Inst) {
    dbgs() << "Untranslated instruction andn\n";
    exit(-1);
}
void X86Translator::translate_andnpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction andnpd\n";
    exit(-1);
}
void X86Translator::translate_andnps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction andnps\n";
    exit(-1);
}
void X86Translator::translate_andpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction andpd\n";
    exit(-1);
}
void X86Translator::translate_andps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction andps\n";
    exit(-1);
}
void X86Translator::translate_arpl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction arpl\n";
    exit(-1);
}
void X86Translator::translate_bextr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bextr\n";
    exit(-1);
}
void X86Translator::translate_blcfill(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blcfill\n";
    exit(-1);
}
void X86Translator::translate_blci(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blci\n";
    exit(-1);
}
void X86Translator::translate_blcic(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blcic\n";
    exit(-1);
}
void X86Translator::translate_blcmsk(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blcmsk\n";
    exit(-1);
}
void X86Translator::translate_blcs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blcs\n";
    exit(-1);
}
void X86Translator::translate_blendpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blendpd\n";
    exit(-1);
}
void X86Translator::translate_blendps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blendps\n";
    exit(-1);
}
void X86Translator::translate_blendvpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blendvpd\n";
    exit(-1);
}
void X86Translator::translate_blendvps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blendvps\n";
    exit(-1);
}
void X86Translator::translate_blsfill(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blsfill\n";
    exit(-1);
}
void X86Translator::translate_blsi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blsi\n";
    exit(-1);
}
void X86Translator::translate_blsic(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blsic\n";
    exit(-1);
}
void X86Translator::translate_blsmsk(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blsmsk\n";
    exit(-1);
}
void X86Translator::translate_blsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction blsr\n";
    exit(-1);
}
void X86Translator::translate_bound(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bound\n";
    exit(-1);
}
void X86Translator::translate_bzhi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bzhi\n";
    exit(-1);
}
void X86Translator::translate_call(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    // adjust esp
    Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
    Value *NewESP = Builder.CreateSub(OldESP, ConstInt(Int64Ty, 8));
    StoreGMRValue(NewESP, X86Config::RSP);

    // store return address into stack
    Value *NewESPPtr = Builder.CreateIntToPtr(NewESP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), NewESPPtr);

    // sync GMRVals into stack.
    SyncAllGMRValue();

    // store call target into env.
    X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
    if (OpndHdl.isImm()) { // can do link
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
        Value *Func = Mod->getOrInsertFunction("llvm.loongarch.cogbtexit", FTy);
        Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
        Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());

        BindPhysicalReg();
        Instruction *LinkSlot = Builder.CreateCall(FTy, Func, {TargetPC, Off});
        AttachLinkInfoToIR(LinkSlot, LI_TBLINK, 1);
        Builder.CreateCall(Mod->getFunction("epilogue"));
        Builder.CreateUnreachable();
        ExitBB->eraseFromParent();
    } else {
        Value *Target = LoadOperand(InstHdl.getOpnd(0));
        Value *EnvEIP = Builder.CreateGEP(Int8Ty, CPUEnv,
                                          ConstInt(Int64Ty, GuestEIPOffset()));
        Value *EIPAddr =
            Builder.CreateBitCast(EnvEIP, Target->getType()->getPointerTo());
        Builder.CreateStore(Target, EIPAddr);
        Builder.CreateBr(ExitBB);
    }
}
void X86Translator::translate_cbw(GuestInst *Inst) {
    // AX = sign-extend of AL
    X86InstHandler InstHdl(Inst);
    Value *AL = LoadGMRValue(Int8Ty, X86Config::RAX);
    Value *V = Builder.CreateSExt(AL, Int16Ty);
    StoreGMRValue(V, X86Config::RAX);
}
void X86Translator::translate_cdq(GuestInst *Inst) {
    // EDX:EAX = sign-extend of EAX
    X86InstHandler InstHdl(Inst);
    Value *EAX = LoadGMRValue(Int32Ty, X86Config::RAX);
    Value *V = Builder.CreateSExt(EAX, Int64Ty);
    V = Builder.CreateLShr(V, ConstInt(Int64Ty, 32));
    StoreGMRValue(V, X86Config::RDX);
}
void X86Translator::translate_cdqe(GuestInst *Inst) {
    // RAX = sign-extend of EAX
    X86InstHandler InstHdl(Inst);
    Value *EAX = LoadGMRValue(Int32Ty, X86Config::RAX);
    Value *V = Builder.CreateSExt(EAX, Int64Ty);
    StoreGMRValue(V, X86Config::RAX);
}
void X86Translator::translate_fchs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fchs\n";
    exit(-1);
}
void X86Translator::translate_clac(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clac\n";
    exit(-1);
}
void X86Translator::translate_clc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clc\n";
    exit(-1);
}
void X86Translator::translate_cld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cld\n";
    exit(-1);
}
void X86Translator::translate_clflush(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clflush\n";
    exit(-1);
}
void X86Translator::translate_clflushopt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clflushopt\n";
    exit(-1);
}
void X86Translator::translate_clgi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clgi\n";
    exit(-1);
}
void X86Translator::translate_cli(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cli\n";
    exit(-1);
}
void X86Translator::translate_clts(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clts\n";
    exit(-1);
}
void X86Translator::translate_clwb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction clwb\n";
    exit(-1);
}
void X86Translator::translate_cmc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmc\n";
    exit(-1);
}
/* void X86Translator::translate_cmp(GuestInst *Inst) { */
/*     dbgs() << "Untranslated instruction cmp\n"; */
/*     exit(-1); */
/* } */
void X86Translator::translate_cmpsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpsb\n";
    exit(-1);
}
void X86Translator::translate_cmpsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpsq\n";
    exit(-1);
}
void X86Translator::translate_cmpsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpsw\n";
    exit(-1);
}
void X86Translator::translate_comisd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction comisd\n";
    exit(-1);
}
void X86Translator::translate_fcomp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomp\n";
    exit(-1);
}
void X86Translator::translate_fcomip(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomip\n";
    exit(-1);
}
void X86Translator::translate_fcomi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcomi\n";
    exit(-1);
}
void X86Translator::translate_fcom(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcom\n";
    exit(-1);
}
void X86Translator::translate_fcos(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcos\n";
    exit(-1);
}
void X86Translator::translate_cpuid(GuestInst *Inst) {
    /* for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) { */
    /*     if (GMRVals[GMRId].isDirty()) { */
    /*         Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]); */
    /*         GMRVals[GMRId].setDirty(false); */
    /*     } */
    /* } */
    // Sync 
    Value *Addr = nullptr;
    if (GMRVals[X86Config::RAX].hasValue()) {
        Addr = Builder.CreateGEP(Int8Ty, CPUEnv,
                                 ConstInt(Int64Ty, GetEAXOffset()));
        Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
        Builder.CreateStore(GMRVals[X86Config::RAX].getValue(), Addr);
    }
    if (GMRVals[X86Config::RCX].hasValue()) {
        Addr = Builder.CreateGEP(Int8Ty, CPUEnv,
                                 ConstInt(Int64Ty, GetECXOffset()));
        Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
        Builder.CreateStore(GMRVals[X86Config::RCX].getValue(), Addr);
    }

    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
#if (LLVM_VERSION_MAJOR > 8)
    FunctionCallee F = Mod->getOrInsertFunction("helper_cpuid", FuncTy);
    if (F)
        Builder.CreateCall(FuncTy, F.getCallee(), CPUEnv);
#else
    Value *Func = Mod->getOrInsertFunction("helper_cpuid", FuncTy);
    Builder.CreateCall(Func, CPUEnv);
#endif
    // Load eax, ebx, ecx, edx
    Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GetEAXOffset()));
    Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
    StoreGMRValue(Builder.CreateLoad(Int64Ty, Addr), X86Config::RAX);
    Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GetEBXOffset()));
    Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
    StoreGMRValue(Builder.CreateLoad(Int64Ty, Addr), X86Config::RBX);
    Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GetECXOffset()));
    Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
    StoreGMRValue(Builder.CreateLoad(Int64Ty, Addr), X86Config::RCX);
    Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GetEDXOffset()));
    Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
    StoreGMRValue(Builder.CreateLoad(Int64Ty, Addr), X86Config::RDX);
}

void X86Translator::translate_cqo(GuestInst *Inst) {
    Value *Src = LoadGMRValue(Int64Ty, X86Config::RAX);
    Src = Builder.CreateAShr(Src, ConstInt(Int64Ty, 63));
    StoreGMRValue(Src, X86Config::RDX);
}

void X86Translator::translate_crc32(GuestInst *Inst) {
    dbgs() << "Untranslated instruction crc32\n";
    exit(-1);
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
void X86Translator::translate_cvtsi2sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtsi2sd\n";
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
    dbgs() << "Untranslated instruction cvttsd2si\n";
    exit(-1);
}
void X86Translator::translate_cvttss2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttss2si\n";
    exit(-1);
}
void X86Translator::translate_cwd(GuestInst *Inst) {
    // DX:AX = sign-extend of AX
    X86InstHandler InstHdl(Inst);
    Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
    Value *V = Builder.CreateAShr(AX, ConstInt(Int32Ty, 15));
    StoreGMRValue(V, X86Config::RDX);
}
void X86Translator::translate_cwde(GuestInst *Inst) {
    // EAX = sign-extend of AX
    X86InstHandler InstHdl(Inst);
    Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
    Value *V = Builder.CreateSExt(AX, Int32Ty);
    V = Builder.CreateZExt(V, Int64Ty);
    StoreGMRValue(V, X86Config::RAX);
}
void X86Translator::translate_data16(GuestInst *Inst) {
    dbgs() << "Untranslated instruction data16\n";
    exit(-1);
}
void X86Translator::translate_dppd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction dppd\n";
    exit(-1);
}
void X86Translator::translate_dpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction dpps\n";
    exit(-1);
}
void X86Translator::translate_ret(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    // load return address from stack
    Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
    Value *OldESPPtr = Builder.CreateIntToPtr(OldESP, Int64PtrTy);
    Value *RA = Builder.CreateLoad(Int64Ty, OldESPPtr);

    // adjust esp
    Value *NewESP = Builder.CreateAdd(OldESP, ConstInt(Int64Ty, 8));
    StoreGMRValue(NewESP, X86Config::RSP);

    // store return address into env.
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr =
        Builder.CreateBitCast(EnvEIP, Int64Ty->getPointerTo());
    Builder.CreateStore(RA, EIPAddr);

    // sync GMRVals into stack.
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        if (GMRVals[GMRId].isDirty()) {
            Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
        }
    }
    Builder.CreateBr(ExitBB);

}
void X86Translator::translate_encls(GuestInst *Inst) {
    dbgs() << "Untranslated instruction encls\n";
    exit(-1);
}
void X86Translator::translate_enclu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction enclu\n";
    exit(-1);
}
void X86Translator::translate_enter(GuestInst *Inst) {
    dbgs() << "Untranslated instruction enter\n";
    exit(-1);
}
void X86Translator::translate_extractps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction extractps\n";
    exit(-1);
}
void X86Translator::translate_extrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction extrq\n";
    exit(-1);
}
void X86Translator::translate_f2xm1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction f2xm1\n";
    exit(-1);
}
void X86Translator::translate_lcall(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lcall\n";
    exit(-1);
}
void X86Translator::translate_ljmp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ljmp\n";
    exit(-1);
}
void X86Translator::translate_fbld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fbld\n";
    exit(-1);
}
void X86Translator::translate_fbstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fbstp\n";
    exit(-1);
}
void X86Translator::translate_fcompp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcompp\n";
    exit(-1);
}
void X86Translator::translate_fdecstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdecstp\n";
    exit(-1);
}
void X86Translator::translate_femms(GuestInst *Inst) {
    dbgs() << "Untranslated instruction femms\n";
    exit(-1);
}
void X86Translator::translate_ffree(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffree\n";
    exit(-1);
}
void X86Translator::translate_ficom(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ficom\n";
    exit(-1);
}
void X86Translator::translate_ficomp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ficomp\n";
    exit(-1);
}
void X86Translator::translate_fincstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fincstp\n";
    exit(-1);
}
void X86Translator::translate_fldcw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldcw\n";
    exit(-1);
}
void X86Translator::translate_fldenv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldenv\n";
    exit(-1);
}
void X86Translator::translate_fldl2e(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldl2e\n";
    exit(-1);
}
void X86Translator::translate_fldl2t(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldl2t\n";
    exit(-1);
}
void X86Translator::translate_fldlg2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldlg2\n";
    exit(-1);
}
void X86Translator::translate_fldln2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldln2\n";
    exit(-1);
}
void X86Translator::translate_fldpi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldpi\n";
    exit(-1);
}
void X86Translator::translate_fnclex(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnclex\n";
    exit(-1);
}
void X86Translator::translate_fninit(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fninit\n";
    exit(-1);
}
void X86Translator::translate_fnop(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnop\n";
    exit(-1);
}
void X86Translator::translate_fnstcw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnstcw\n";
    exit(-1);
}
void X86Translator::translate_fnstsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnstsw\n";
    exit(-1);
}
void X86Translator::translate_fpatan(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fpatan\n";
    exit(-1);
}
void X86Translator::translate_fprem(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fprem\n";
    exit(-1);
}
void X86Translator::translate_fprem1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fprem1\n";
    exit(-1);
}
void X86Translator::translate_fptan(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fptan\n";
    exit(-1);
}
void X86Translator::translate_ffreep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ffreep\n";
    exit(-1);
}
void X86Translator::translate_frndint(GuestInst *Inst) {
    dbgs() << "Untranslated instruction frndint\n";
    exit(-1);
}
void X86Translator::translate_frstor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction frstor\n";
    exit(-1);
}
void X86Translator::translate_fnsave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnsave\n";
    exit(-1);
}
void X86Translator::translate_fscale(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fscale\n";
    exit(-1);
}
void X86Translator::translate_fsetpm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsetpm\n";
    exit(-1);
}
void X86Translator::translate_fsincos(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsincos\n";
    exit(-1);
}
void X86Translator::translate_fnstenv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fnstenv\n";
    exit(-1);
}
void X86Translator::translate_fxam(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxam\n";
    exit(-1);
}
void X86Translator::translate_fxrstor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxrstor\n";
    exit(-1);
}
void X86Translator::translate_fxrstor64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxrstor64\n";
    exit(-1);
}
void X86Translator::translate_fxsave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxsave\n";
    exit(-1);
}
void X86Translator::translate_fxsave64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxsave64\n";
    exit(-1);
}
void X86Translator::translate_fxtract(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxtract\n";
    exit(-1);
}
void X86Translator::translate_fyl2x(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fyl2x\n";
    exit(-1);
}
void X86Translator::translate_fyl2xp1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fyl2xp1\n";
    exit(-1);
}
void X86Translator::translate_movapd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movapd\n";
    exit(-1);
}
void X86Translator::translate_orpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction orpd\n";
    exit(-1);
}
void X86Translator::translate_orps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction orps\n";
    exit(-1);
}
void X86Translator::translate_vmovapd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovapd\n";
    exit(-1);
}
void X86Translator::translate_vmovaps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovaps\n";
    exit(-1);
}
void X86Translator::translate_xorpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xorpd\n";
    exit(-1);
}
void X86Translator::translate_xorps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xorps\n";
    exit(-1);
}
void X86Translator::translate_getsec(GuestInst *Inst) {
    dbgs() << "Untranslated instruction getsec\n";
    exit(-1);
}
void X86Translator::translate_haddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction haddpd\n";
    exit(-1);
}
void X86Translator::translate_haddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction haddps\n";
    exit(-1);
}
void X86Translator::translate_hlt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction hlt\n";
    exit(-1);
}
void X86Translator::translate_hsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction hsubpd\n";
    exit(-1);
}
void X86Translator::translate_hsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction hsubps\n";
    exit(-1);
}
void X86Translator::translate_fild(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fild\n";
    exit(-1);
}
void X86Translator::translate_in(GuestInst *Inst) {
    dbgs() << "Untranslated instruction in\n";
    exit(-1);
}
void X86Translator::translate_insb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction insb\n";
    exit(-1);
}
void X86Translator::translate_insertps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction insertps\n";
    exit(-1);
}
void X86Translator::translate_insertq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction insertq\n";
    exit(-1);
}
void X86Translator::translate_insd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction insd\n";
    exit(-1);
}
void X86Translator::translate_insw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction insw\n";
    exit(-1);
}
void X86Translator::translate_int(GuestInst *Inst) {
    dbgs() << "Untranslated instruction int\n";
    exit(-1);
}
void X86Translator::translate_int1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction int1\n";
    exit(-1);
}
void X86Translator::translate_int3(GuestInst *Inst) {
    dbgs() << "Untranslated instruction int3\n";
    exit(-1);
}
void X86Translator::translate_into(GuestInst *Inst) {
    dbgs() << "Untranslated instruction into\n";
    exit(-1);
}
void X86Translator::translate_invd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invd\n";
    exit(-1);
}
void X86Translator::translate_invept(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invept\n";
    exit(-1);
}
void X86Translator::translate_invlpg(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invlpg\n";
    exit(-1);
}
void X86Translator::translate_invlpga(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invlpga\n";
    exit(-1);
}
void X86Translator::translate_invpcid(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invpcid\n";
    exit(-1);
}
void X86Translator::translate_invvpid(GuestInst *Inst) {
    dbgs() << "Untranslated instruction invvpid\n";
    exit(-1);
}
void X86Translator::translate_iret(GuestInst *Inst) {
    dbgs() << "Untranslated instruction iret\n";
    exit(-1);
}
void X86Translator::translate_iretd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction iretd\n";
    exit(-1);
}
void X86Translator::translate_iretq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction iretq\n";
    exit(-1);
}
void X86Translator::translate_fisttp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fisttp\n";
    exit(-1);
}
void X86Translator::translate_fist(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fist\n";
    exit(-1);
}
void X86Translator::translate_fistp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fistp\n";
    exit(-1);
}
void X86Translator::translate_ucomisd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ucomisd\n";
    exit(-1);
}
void X86Translator::translate_ucomiss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ucomiss\n";
    exit(-1);
}
void X86Translator::translate_vcomisd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcomisd\n";
    exit(-1);
}
void X86Translator::translate_vcomiss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcomiss\n";
    exit(-1);
}
void X86Translator::translate_vcvtsd2ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtsd2ss\n";
    exit(-1);
}
void X86Translator::translate_vcvtsi2sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtsi2sd\n";
    exit(-1);
}
void X86Translator::translate_vcvtsi2ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtsi2ss\n";
    exit(-1);
}
void X86Translator::translate_vcvtss2sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtss2sd\n";
    exit(-1);
}
void X86Translator::translate_vcvttsd2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttsd2si\n";
    exit(-1);
}
void X86Translator::translate_vcvttsd2usi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttsd2usi\n";
    exit(-1);
}
void X86Translator::translate_vcvttss2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttss2si\n";
    exit(-1);
}
void X86Translator::translate_vcvttss2usi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttss2usi\n";
    exit(-1);
}
void X86Translator::translate_vcvtusi2sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtusi2sd\n";
    exit(-1);
}
void X86Translator::translate_vcvtusi2ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtusi2ss\n";
    exit(-1);
}
void X86Translator::translate_vucomisd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vucomisd\n";
    exit(-1);
}
void X86Translator::translate_vucomiss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vucomiss\n";
    exit(-1);
}
void X86Translator::translate_kandb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandb\n";
    exit(-1);
}
void X86Translator::translate_kandd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandd\n";
    exit(-1);
}
void X86Translator::translate_kandnb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandnb\n";
    exit(-1);
}
void X86Translator::translate_kandnd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandnd\n";
    exit(-1);
}
void X86Translator::translate_kandnq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandnq\n";
    exit(-1);
}
void X86Translator::translate_kandnw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandnw\n";
    exit(-1);
}
void X86Translator::translate_kandq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandq\n";
    exit(-1);
}
void X86Translator::translate_kandw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kandw\n";
    exit(-1);
}
void X86Translator::translate_kmovb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kmovb\n";
    exit(-1);
}
void X86Translator::translate_kmovd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kmovd\n";
    exit(-1);
}
void X86Translator::translate_kmovq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kmovq\n";
    exit(-1);
}
void X86Translator::translate_kmovw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kmovw\n";
    exit(-1);
}
void X86Translator::translate_knotb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction knotb\n";
    exit(-1);
}
void X86Translator::translate_knotd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction knotd\n";
    exit(-1);
}
void X86Translator::translate_knotq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction knotq\n";
    exit(-1);
}
void X86Translator::translate_knotw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction knotw\n";
    exit(-1);
}
void X86Translator::translate_korb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction korb\n";
    exit(-1);
}
void X86Translator::translate_kord(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kord\n";
    exit(-1);
}
void X86Translator::translate_korq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction korq\n";
    exit(-1);
}
void X86Translator::translate_kortestb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kortestb\n";
    exit(-1);
}
void X86Translator::translate_kortestd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kortestd\n";
    exit(-1);
}
void X86Translator::translate_kortestq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kortestq\n";
    exit(-1);
}
void X86Translator::translate_kortestw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kortestw\n";
    exit(-1);
}
void X86Translator::translate_korw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction korw\n";
    exit(-1);
}
void X86Translator::translate_kshiftlb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftlb\n";
    exit(-1);
}
void X86Translator::translate_kshiftld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftld\n";
    exit(-1);
}
void X86Translator::translate_kshiftlq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftlq\n";
    exit(-1);
}
void X86Translator::translate_kshiftlw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftlw\n";
    exit(-1);
}
void X86Translator::translate_kshiftrb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftrb\n";
    exit(-1);
}
void X86Translator::translate_kshiftrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftrd\n";
    exit(-1);
}
void X86Translator::translate_kshiftrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftrq\n";
    exit(-1);
}
void X86Translator::translate_kshiftrw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kshiftrw\n";
    exit(-1);
}
void X86Translator::translate_kunpckbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kunpckbw\n";
    exit(-1);
}
void X86Translator::translate_kxnorb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxnorb\n";
    exit(-1);
}
void X86Translator::translate_kxnord(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxnord\n";
    exit(-1);
}
void X86Translator::translate_kxnorq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxnorq\n";
    exit(-1);
}
void X86Translator::translate_kxnorw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxnorw\n";
    exit(-1);
}
void X86Translator::translate_kxorb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxorb\n";
    exit(-1);
}
void X86Translator::translate_kxord(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxord\n";
    exit(-1);
}
void X86Translator::translate_kxorq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxorq\n";
    exit(-1);
}
void X86Translator::translate_kxorw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction kxorw\n";
    exit(-1);
}
void X86Translator::translate_lahf(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lahf\n";
    exit(-1);
}
void X86Translator::translate_lar(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lar\n";
    exit(-1);
}
void X86Translator::translate_lddqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lddqu\n";
    exit(-1);
}
void X86Translator::translate_ldmxcsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ldmxcsr\n";
    exit(-1);
}
void X86Translator::translate_lds(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lds\n";
    exit(-1);
}
void X86Translator::translate_fldz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fldz\n";
    exit(-1);
}
void X86Translator::translate_fld1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fld1\n";
    exit(-1);
}
void X86Translator::translate_fld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fld\n";
    exit(-1);
}
/* void X86Translator::translate_lea(GuestInst *Inst) { */
/*     dbgs() << "Untranslated instruction lea\n"; */
/*     exit(-1); */
/* } */
void X86Translator::translate_leave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction leave\n";
    exit(-1);
}
void X86Translator::translate_les(GuestInst *Inst) {
    dbgs() << "Untranslated instruction les\n";
    exit(-1);
}
void X86Translator::translate_lfence(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lfence\n";
    exit(-1);
}
void X86Translator::translate_lfs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lfs\n";
    exit(-1);
}
void X86Translator::translate_lgdt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lgdt\n";
    exit(-1);
}
void X86Translator::translate_lgs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lgs\n";
    exit(-1);
}
void X86Translator::translate_lidt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lidt\n";
    exit(-1);
}
void X86Translator::translate_lldt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lldt\n";
    exit(-1);
}
void X86Translator::translate_lmsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lmsw\n";
    exit(-1);
}
/* void X86Translator::translate_sub(GuestInst *Inst) { */
/*     dbgs() << "Untranslated instruction sub\n"; */
/*     exit(-1); */
/* } */
/* void X86Translator::translate_xor(GuestInst *Inst) { */
/*     dbgs() << "Untranslated instruction xor\n"; */
/*     exit(-1); */
/* } */
void X86Translator::translate_lodsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lodsb\n";
    exit(-1);
}
void X86Translator::translate_lodsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lodsd\n";
    exit(-1);
}
void X86Translator::translate_lodsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lodsq\n";
    exit(-1);
}
void X86Translator::translate_lodsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lodsw\n";
    exit(-1);
}
void X86Translator::translate_loop(GuestInst *Inst) {
    dbgs() << "Untranslated instruction loop\n";
    exit(-1);
}
void X86Translator::translate_loope(GuestInst *Inst) {
    dbgs() << "Untranslated instruction loope\n";
    exit(-1);
}
void X86Translator::translate_loopne(GuestInst *Inst) {
    dbgs() << "Untranslated instruction loopne\n";
    exit(-1);
}
void X86Translator::translate_retf(GuestInst *Inst) {
    dbgs() << "Untranslated instruction retf\n";
    exit(-1);
}
void X86Translator::translate_retfq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction retfq\n";
    exit(-1);
}
void X86Translator::translate_lsl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lsl\n";
    exit(-1);
}
void X86Translator::translate_lss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lss\n";
    exit(-1);
}
void X86Translator::translate_ltr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ltr\n";
    exit(-1);
}
void X86Translator::translate_lzcnt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction lzcnt\n";
    exit(-1);
}
void X86Translator::translate_maskmovdqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction maskmovdqu\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction maxsd\n";
    exit(-1);
}
void X86Translator::translate_maxss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction maxss\n";
    exit(-1);
}
void X86Translator::translate_mfence(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mfence\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction minsd\n";
    exit(-1);
}
void X86Translator::translate_minss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction minss\n";
    exit(-1);
}
void X86Translator::translate_cvtpd2pi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtpd2pi\n";
    exit(-1);
}
void X86Translator::translate_cvtpi2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtpi2pd\n";
    exit(-1);
}
void X86Translator::translate_cvtpi2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtpi2ps\n";
    exit(-1);
}
void X86Translator::translate_cvtps2pi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvtps2pi\n";
    exit(-1);
}
void X86Translator::translate_cvttpd2pi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttpd2pi\n";
    exit(-1);
}
void X86Translator::translate_cvttps2pi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cvttps2pi\n";
    exit(-1);
}
void X86Translator::translate_emms(GuestInst *Inst) {
    dbgs() << "Untranslated instruction emms\n";
    exit(-1);
}
void X86Translator::translate_maskmovq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction maskmovq\n";
    exit(-1);
}
void X86Translator::translate_movdq2q(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movdq2q\n";
    exit(-1);
}
void X86Translator::translate_movntq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntq\n";
    exit(-1);
}
void X86Translator::translate_movq2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movq2dq\n";
    exit(-1);
}
void X86Translator::translate_pabsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pabsb\n";
    exit(-1);
}
void X86Translator::translate_pabsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pabsd\n";
    exit(-1);
}
void X86Translator::translate_pabsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pabsw\n";
    exit(-1);
}
void X86Translator::translate_packssdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction packssdw\n";
    exit(-1);
}
void X86Translator::translate_packsswb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction packsswb\n";
    exit(-1);
}
void X86Translator::translate_packuswb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction packuswb\n";
    exit(-1);
}
void X86Translator::translate_palignr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction palignr\n";
    exit(-1);
}
void X86Translator::translate_pextrw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pextrw\n";
    exit(-1);
}
void X86Translator::translate_phaddsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phaddsw\n";
    exit(-1);
}
void X86Translator::translate_phaddw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phaddw\n";
    exit(-1);
}
void X86Translator::translate_phaddd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phaddd\n";
    exit(-1);
}
void X86Translator::translate_phsubd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phsubd\n";
    exit(-1);
}
void X86Translator::translate_phsubsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phsubsw\n";
    exit(-1);
}
void X86Translator::translate_phsubw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phsubw\n";
    exit(-1);
}
void X86Translator::translate_pinsrw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pinsrw\n";
    exit(-1);
}
void X86Translator::translate_pmaddubsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmaddubsw\n";
    exit(-1);
}
void X86Translator::translate_pmulhrsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmulhrsw\n";
    exit(-1);
}
void X86Translator::translate_pshufb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pshufb\n";
    exit(-1);
}
void X86Translator::translate_pshufw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pshufw\n";
    exit(-1);
}
void X86Translator::translate_psignb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psignb\n";
    exit(-1);
}
void X86Translator::translate_psignd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psignd\n";
    exit(-1);
}
void X86Translator::translate_psignw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psignw\n";
    exit(-1);
}
void X86Translator::translate_pslld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pslld\n";
    exit(-1);
}
void X86Translator::translate_psllq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psllq\n";
    exit(-1);
}
void X86Translator::translate_psllw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psllw\n";
    exit(-1);
}
void X86Translator::translate_psrad(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psrad\n";
    exit(-1);
}
void X86Translator::translate_psraw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psraw\n";
    exit(-1);
}
void X86Translator::translate_psrld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psrld\n";
    exit(-1);
}
void X86Translator::translate_psrlq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psrlq\n";
    exit(-1);
}
void X86Translator::translate_psrlw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psrlw\n";
    exit(-1);
}
void X86Translator::translate_monitor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction monitor\n";
    exit(-1);
}
void X86Translator::translate_montmul(GuestInst *Inst) {
    dbgs() << "Untranslated instruction montmul\n";
    exit(-1);
}
void X86Translator::translate_mwait(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mwait\n";
    exit(-1);
}
void X86Translator::translate_out(GuestInst *Inst) {
    dbgs() << "Untranslated instruction out\n";
    exit(-1);
}
void X86Translator::translate_outsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction outsb\n";
    exit(-1);
}
void X86Translator::translate_outsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction outsd\n";
    exit(-1);
}
void X86Translator::translate_outsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction outsw\n";
    exit(-1);
}
void X86Translator::translate_packusdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction packusdw\n";
    exit(-1);
}
void X86Translator::translate_pause(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pause\n";
    exit(-1);
}
void X86Translator::translate_pavgusb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pavgusb\n";
    exit(-1);
}
void X86Translator::translate_pblendvb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pblendvb\n";
    exit(-1);
}
void X86Translator::translate_pblendw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pblendw\n";
    exit(-1);
}
void X86Translator::translate_pclmulqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pclmulqdq\n";
    exit(-1);
}
void X86Translator::translate_pcmpeqq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpeqq\n";
    exit(-1);
}
void X86Translator::translate_pcmpestri(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpestri\n";
    exit(-1);
}
void X86Translator::translate_pcmpestrm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpestrm\n";
    exit(-1);
}
void X86Translator::translate_pcmpgtq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpgtq\n";
    exit(-1);
}
void X86Translator::translate_pcmpistri(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpistri\n";
    exit(-1);
}
void X86Translator::translate_pcmpistrm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcmpistrm\n";
    exit(-1);
}
void X86Translator::translate_pcommit(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pcommit\n";
    exit(-1);
}
void X86Translator::translate_pdep(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pdep\n";
    exit(-1);
}
void X86Translator::translate_pext(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pext\n";
    exit(-1);
}
void X86Translator::translate_pextrb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pextrb\n";
    exit(-1);
}
void X86Translator::translate_pextrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pextrd\n";
    exit(-1);
}
void X86Translator::translate_pextrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pextrq\n";
    exit(-1);
}
void X86Translator::translate_pf2id(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pf2id\n";
    exit(-1);
}
void X86Translator::translate_pf2iw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pf2iw\n";
    exit(-1);
}
void X86Translator::translate_pfacc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfacc\n";
    exit(-1);
}
void X86Translator::translate_pfadd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfadd\n";
    exit(-1);
}
void X86Translator::translate_pfcmpeq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfcmpeq\n";
    exit(-1);
}
void X86Translator::translate_pfcmpge(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfcmpge\n";
    exit(-1);
}
void X86Translator::translate_pfcmpgt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfcmpgt\n";
    exit(-1);
}
void X86Translator::translate_pfmax(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfmax\n";
    exit(-1);
}
void X86Translator::translate_pfmin(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfmin\n";
    exit(-1);
}
void X86Translator::translate_pfmul(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfmul\n";
    exit(-1);
}
void X86Translator::translate_pfnacc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfnacc\n";
    exit(-1);
}
void X86Translator::translate_pfpnacc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfpnacc\n";
    exit(-1);
}
void X86Translator::translate_pfrcpit1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfrcpit1\n";
    exit(-1);
}
void X86Translator::translate_pfrcpit2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfrcpit2\n";
    exit(-1);
}
void X86Translator::translate_pfrcp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfrcp\n";
    exit(-1);
}
void X86Translator::translate_pfrsqit1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfrsqit1\n";
    exit(-1);
}
void X86Translator::translate_pfrsqrt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfrsqrt\n";
    exit(-1);
}
void X86Translator::translate_pfsubr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfsubr\n";
    exit(-1);
}
void X86Translator::translate_pfsub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pfsub\n";
    exit(-1);
}
void X86Translator::translate_phminposuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction phminposuw\n";
    exit(-1);
}
void X86Translator::translate_pi2fd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pi2fd\n";
    exit(-1);
}
void X86Translator::translate_pi2fw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pi2fw\n";
    exit(-1);
}
void X86Translator::translate_pinsrb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pinsrb\n";
    exit(-1);
}
void X86Translator::translate_pinsrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pinsrd\n";
    exit(-1);
}
void X86Translator::translate_pinsrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pinsrq\n";
    exit(-1);
}
void X86Translator::translate_pmaxsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmaxsb\n";
    exit(-1);
}
void X86Translator::translate_pmaxsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmaxsd\n";
    exit(-1);
}
void X86Translator::translate_pmaxud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmaxud\n";
    exit(-1);
}
void X86Translator::translate_pmaxuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmaxuw\n";
    exit(-1);
}
void X86Translator::translate_pminsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pminsb\n";
    exit(-1);
}
void X86Translator::translate_pminsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pminsd\n";
    exit(-1);
}
void X86Translator::translate_pminud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pminud\n";
    exit(-1);
}
void X86Translator::translate_pminuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pminuw\n";
    exit(-1);
}
void X86Translator::translate_pmovsxbd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxbd\n";
    exit(-1);
}
void X86Translator::translate_pmovsxbq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxbq\n";
    exit(-1);
}
void X86Translator::translate_pmovsxbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxbw\n";
    exit(-1);
}
void X86Translator::translate_pmovsxdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxdq\n";
    exit(-1);
}
void X86Translator::translate_pmovsxwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxwd\n";
    exit(-1);
}
void X86Translator::translate_pmovsxwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovsxwq\n";
    exit(-1);
}
void X86Translator::translate_pmovzxbd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxbd\n";
    exit(-1);
}
void X86Translator::translate_pmovzxbq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxbq\n";
    exit(-1);
}
void X86Translator::translate_pmovzxbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxbw\n";
    exit(-1);
}
void X86Translator::translate_pmovzxdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxdq\n";
    exit(-1);
}
void X86Translator::translate_pmovzxwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxwd\n";
    exit(-1);
}
void X86Translator::translate_pmovzxwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmovzxwq\n";
    exit(-1);
}
void X86Translator::translate_pmuldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmuldq\n";
    exit(-1);
}
void X86Translator::translate_pmulld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pmulld\n";
    exit(-1);
}
void X86Translator::translate_pop(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
    Type *OpndTy = GetOpndLLVMType(InstHdl.getOpndSize());
    Value *OldESPPtr = Builder.CreateIntToPtr(OldESP, OpndTy->getPointerTo());

    // Load stack value.
    Value *Src = Builder.CreateLoad(OpndTy, OldESPPtr);

    // Store value.
    StoreOperand(Src, InstHdl.getOpnd(0));

    // Adjust ESP value.
    Value *NewESP =
        Builder.CreateAdd(OldESP, ConstInt(Int64Ty, InstHdl.getOpndSize()));
    StoreGMRValue(NewESP, X86Config::RSP);
}
void X86Translator::translate_popaw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popaw\n";
    exit(-1);
}
void X86Translator::translate_popal(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popal\n";
    exit(-1);
}
void X86Translator::translate_popcnt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popcnt\n";
    exit(-1);
}
void X86Translator::translate_popf(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popf\n";
    exit(-1);
}
void X86Translator::translate_popfd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popfd\n";
    exit(-1);
}
void X86Translator::translate_popfq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction popfq\n";
    exit(-1);
}
void X86Translator::translate_prefetch(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetch\n";
    exit(-1);
}
void X86Translator::translate_prefetchnta(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetchnta\n";
    exit(-1);
}
void X86Translator::translate_prefetcht0(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetcht0\n";
    exit(-1);
}
void X86Translator::translate_prefetcht1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetcht1\n";
    exit(-1);
}
void X86Translator::translate_prefetcht2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetcht2\n";
    exit(-1);
}
void X86Translator::translate_prefetchw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction prefetchw\n";
    exit(-1);
}
void X86Translator::translate_pslldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pslldq\n";
    exit(-1);
}
void X86Translator::translate_psrldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction psrldq\n";
    exit(-1);
}
void X86Translator::translate_pswapd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pswapd\n";
    exit(-1);
}
void X86Translator::translate_ptest(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ptest\n";
    exit(-1);
}
void X86Translator::translate_punpckhqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpckhqdq\n";
    exit(-1);
}
void X86Translator::translate_punpcklqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction punpcklqdq\n";
    exit(-1);
}
void X86Translator::translate_push(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    // Calculate new esp.
    Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
    Value *NewESP =
        Builder.CreateSub(OldESP, ConstInt(Int64Ty, InstHdl.getOpndSize()));

    // Store src value into stack.
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *NewESPPtr = Builder.CreateIntToPtr(
        NewESP, GetOpndLLVMType(InstHdl.getOpndSize())->getPointerTo());
    Builder.CreateStore(Src, NewESPPtr);

    StoreGMRValue(NewESP, X86Config::RSP);
    /* dbgs() << "Untranslated instruction push\n"; */
    /* exit(-1); */
}
void X86Translator::translate_pushaw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pushaw\n";
    exit(-1);
}
void X86Translator::translate_pushal(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pushal\n";
    exit(-1);
}
void X86Translator::translate_pushf(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pushf\n";
    exit(-1);
}
void X86Translator::translate_pushfd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pushfd\n";
    exit(-1);
}
void X86Translator::translate_pushfq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction pushfq\n";
    exit(-1);
}
void X86Translator::translate_rcl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rcl\n";
    exit(-1);
}
void X86Translator::translate_rcpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rcpps\n";
    exit(-1);
}
void X86Translator::translate_rcpss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rcpss\n";
    exit(-1);
}
void X86Translator::translate_rcr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rcr\n";
    exit(-1);
}
void X86Translator::translate_rdfsbase(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdfsbase\n";
    exit(-1);
}
void X86Translator::translate_rdgsbase(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdgsbase\n";
    exit(-1);
}
void X86Translator::translate_rdmsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdmsr\n";
    exit(-1);
}
void X86Translator::translate_rdpmc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdpmc\n";
    exit(-1);
}
void X86Translator::translate_rdrand(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdrand\n";
    exit(-1);
}
void X86Translator::translate_rdseed(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdseed\n";
    exit(-1);
}

void X86Translator::translate_rdtsc(GuestInst *Inst) {
    FunctionType *FuncTy = FunctionType::get(VoidTy, Int8PtrTy, false);
#if (LLVM_VERSION_MAJOR > 8)
    FunctionCallee F = Mod->getOrInsertFunction("helper_rdtsc", FuncTy);
    Builder.CreateCall(FuncTy, F.getCallee(), CPUEnv);
#else
    Value *Func = Mod->getOrInsertFunction("helper_rdtsc", FuncTy);
    Builder.CreateCall(Func, CPUEnv);
#endif
    ReloadGMRValue(X86Config::RAX);
    ReloadGMRValue(X86Config::RDX);
}

void X86Translator::translate_rdtscp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rdtscp\n";
    exit(-1);
}
void X86Translator::translate_roundpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction roundpd\n";
    exit(-1);
}
void X86Translator::translate_roundps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction roundps\n";
    exit(-1);
}
void X86Translator::translate_roundsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction roundsd\n";
    exit(-1);
}
void X86Translator::translate_roundss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction roundss\n";
    exit(-1);
}
void X86Translator::translate_rsm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rsm\n";
    exit(-1);
}
void X86Translator::translate_rsqrtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rsqrtps\n";
    exit(-1);
}
void X86Translator::translate_rsqrtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction rsqrtss\n";
    exit(-1);
}
void X86Translator::translate_sahf(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sahf\n";
    exit(-1);
}
void X86Translator::translate_sal(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sal\n";
    exit(-1);
}
void X86Translator::translate_salc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction salc\n";
    exit(-1);
}
void X86Translator::translate_sarx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sarx\n";
    exit(-1);
}
void X86Translator::translate_scasb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction scasb\n";
    exit(-1);
}
void X86Translator::translate_scasd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction scasd\n";
    exit(-1);
}
void X86Translator::translate_scasq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction scasq\n";
    exit(-1);
}
void X86Translator::translate_scasw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction scasw\n";
    exit(-1);
}
void X86Translator::translate_sfence(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sfence\n";
    exit(-1);
}
void X86Translator::translate_sgdt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sgdt\n";
    exit(-1);
}
void X86Translator::translate_sha1msg1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha1msg1\n";
    exit(-1);
}
void X86Translator::translate_sha1msg2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha1msg2\n";
    exit(-1);
}
void X86Translator::translate_sha1nexte(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha1nexte\n";
    exit(-1);
}
void X86Translator::translate_sha1rnds4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha1rnds4\n";
    exit(-1);
}
void X86Translator::translate_sha256msg1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha256msg1\n";
    exit(-1);
}
void X86Translator::translate_sha256msg2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha256msg2\n";
    exit(-1);
}
void X86Translator::translate_sha256rnds2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sha256rnds2\n";
    exit(-1);
}
void X86Translator::translate_shufpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shufpd\n";
    exit(-1);
}
void X86Translator::translate_shufps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction shufps\n";
    exit(-1);
}
void X86Translator::translate_sidt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sidt\n";
    exit(-1);
}
void X86Translator::translate_fsin(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsin\n";
    exit(-1);
}
void X86Translator::translate_skinit(GuestInst *Inst) {
    dbgs() << "Untranslated instruction skinit\n";
    exit(-1);
}
void X86Translator::translate_sldt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sldt\n";
    exit(-1);
}
void X86Translator::translate_smsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction smsw\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction sqrtsd\n";
    exit(-1);
}
void X86Translator::translate_sqrtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sqrtss\n";
    exit(-1);
}
void X86Translator::translate_fsqrt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsqrt\n";
    exit(-1);
}
void X86Translator::translate_stac(GuestInst *Inst) {
    dbgs() << "Untranslated instruction stac\n";
    exit(-1);
}
void X86Translator::translate_stc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction stc\n";
    exit(-1);
}
void X86Translator::translate_std(GuestInst *Inst) {
    dbgs() << "Untranslated instruction std\n";
    exit(-1);
}
void X86Translator::translate_stgi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction stgi\n";
    exit(-1);
}
void X86Translator::translate_sti(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sti\n";
    exit(-1);
}
void X86Translator::translate_stmxcsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction stmxcsr\n";
    exit(-1);
}
void X86Translator::translate_str(GuestInst *Inst) {
    dbgs() << "Untranslated instruction str\n";
    exit(-1);
}
void X86Translator::translate_fst(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fst\n";
    exit(-1);
}
void X86Translator::translate_fstp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstp\n";
    exit(-1);
}
void X86Translator::translate_fstpnce(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fstpnce\n";
    exit(-1);
}
void X86Translator::translate_fxch(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fxch\n";
    exit(-1);
}
void X86Translator::translate_subpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subpd\n";
    exit(-1);
}
void X86Translator::translate_subps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subps\n";
    exit(-1);
}
void X86Translator::translate_fsubr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsubr\n";
    exit(-1);
}
void X86Translator::translate_fisubr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fisubr\n";
    exit(-1);
}
void X86Translator::translate_fsubrp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsubrp\n";
    exit(-1);
}
void X86Translator::translate_subsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subsd\n";
    exit(-1);
}
void X86Translator::translate_subss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction subss\n";
    exit(-1);
}
void X86Translator::translate_fsub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsub\n";
    exit(-1);
}
void X86Translator::translate_fisub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fisub\n";
    exit(-1);
}
void X86Translator::translate_fsubp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fsubp\n";
    exit(-1);
}
void X86Translator::translate_swapgs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction swapgs\n";
    exit(-1);
}
void X86Translator::translate_syscall(GuestInst *Inst) {
    // Save next pc.
    X86InstHandler InstHdl(Inst);
    // Sync all GMR value into env.
    for (int GMRId = 0; GMRId < GetNumGMRs(); GMRId++) {
        FlushGMRValue(GMRId);
    }

    // Call helper_raise_syscall to go back qemu.
    FunctionType *FTy = FunctionType::get(VoidTy, {Int8PtrTy, Int64Ty}, false);
    CallFunc(FTy, "helper_raise_syscall",
             {CPUEnv, ConstInt(Int64Ty, InstHdl.getNextPC())});

    Builder.CreateUnreachable();
    ExitBB->eraseFromParent();
}
void X86Translator::translate_sysenter(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sysenter\n";
    exit(-1);
}
void X86Translator::translate_sysexit(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sysexit\n";
    exit(-1);
}
void X86Translator::translate_sysret(GuestInst *Inst) {
    dbgs() << "Untranslated instruction sysret\n";
    exit(-1);
}
void X86Translator::translate_t1mskc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction t1mskc\n";
    exit(-1);
}

void X86Translator::translate_ud2(GuestInst *Inst) {}

void X86Translator::translate_ftst(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ftst\n";
    exit(-1);
}
void X86Translator::translate_tzcnt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction tzcnt\n";
    exit(-1);
}
void X86Translator::translate_tzmsk(GuestInst *Inst) {
    dbgs() << "Untranslated instruction tzmsk\n";
    exit(-1);
}
void X86Translator::translate_fucomip(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fucomip\n";
    exit(-1);
}
void X86Translator::translate_fucomi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fucomi\n";
    exit(-1);
}
void X86Translator::translate_fucompp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fucompp\n";
    exit(-1);
}
void X86Translator::translate_fucomp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fucomp\n";
    exit(-1);
}
void X86Translator::translate_fucom(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fucom\n";
    exit(-1);
}
void X86Translator::translate_ud2b(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ud2b\n";
    exit(-1);
}
void X86Translator::translate_unpckhpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction unpckhpd\n";
    exit(-1);
}
void X86Translator::translate_unpckhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction unpckhps\n";
    exit(-1);
}
void X86Translator::translate_unpcklpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction unpcklpd\n";
    exit(-1);
}
void X86Translator::translate_unpcklps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction unpcklps\n";
    exit(-1);
}
void X86Translator::translate_vaddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddpd\n";
    exit(-1);
}
void X86Translator::translate_vaddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddps\n";
    exit(-1);
}
void X86Translator::translate_vaddsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddsd\n";
    exit(-1);
}
void X86Translator::translate_vaddss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddss\n";
    exit(-1);
}
void X86Translator::translate_vaddsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddsubpd\n";
    exit(-1);
}
void X86Translator::translate_vaddsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaddsubps\n";
    exit(-1);
}
void X86Translator::translate_vaesdeclast(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaesdeclast\n";
    exit(-1);
}
void X86Translator::translate_vaesdec(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaesdec\n";
    exit(-1);
}
void X86Translator::translate_vaesenclast(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaesenclast\n";
    exit(-1);
}
void X86Translator::translate_vaesenc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaesenc\n";
    exit(-1);
}
void X86Translator::translate_vaesimc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaesimc\n";
    exit(-1);
}
void X86Translator::translate_vaeskeygenassist(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vaeskeygenassist\n";
    exit(-1);
}
void X86Translator::translate_valignd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction valignd\n";
    exit(-1);
}
void X86Translator::translate_valignq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction valignq\n";
    exit(-1);
}
void X86Translator::translate_vandnpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vandnpd\n";
    exit(-1);
}
void X86Translator::translate_vandnps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vandnps\n";
    exit(-1);
}
void X86Translator::translate_vandpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vandpd\n";
    exit(-1);
}
void X86Translator::translate_vandps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vandps\n";
    exit(-1);
}
void X86Translator::translate_vblendmpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendmpd\n";
    exit(-1);
}
void X86Translator::translate_vblendmps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendmps\n";
    exit(-1);
}
void X86Translator::translate_vblendpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendpd\n";
    exit(-1);
}
void X86Translator::translate_vblendps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendps\n";
    exit(-1);
}
void X86Translator::translate_vblendvpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendvpd\n";
    exit(-1);
}
void X86Translator::translate_vblendvps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vblendvps\n";
    exit(-1);
}
void X86Translator::translate_vbroadcastf128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vbroadcastf128\n";
    exit(-1);
}
void X86Translator::translate_vbroadcasti32x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vbroadcasti32x4\n";
    exit(-1);
}
void X86Translator::translate_vbroadcasti64x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vbroadcasti64x4\n";
    exit(-1);
}
void X86Translator::translate_vbroadcastsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vbroadcastsd\n";
    exit(-1);
}
void X86Translator::translate_vbroadcastss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vbroadcastss\n";
    exit(-1);
}
void X86Translator::translate_vcompresspd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcompresspd\n";
    exit(-1);
}
void X86Translator::translate_vcompressps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcompressps\n";
    exit(-1);
}
void X86Translator::translate_vcvtdq2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtdq2pd\n";
    exit(-1);
}
void X86Translator::translate_vcvtdq2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtdq2ps\n";
    exit(-1);
}
void X86Translator::translate_vcvtpd2dqx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtpd2dqx\n";
    exit(-1);
}
void X86Translator::translate_vcvtpd2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtpd2dq\n";
    exit(-1);
}
void X86Translator::translate_vcvtpd2psx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtpd2psx\n";
    exit(-1);
}
void X86Translator::translate_vcvtpd2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtpd2ps\n";
    exit(-1);
}
void X86Translator::translate_vcvtpd2udq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtpd2udq\n";
    exit(-1);
}
void X86Translator::translate_vcvtph2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtph2ps\n";
    exit(-1);
}
void X86Translator::translate_vcvtps2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtps2dq\n";
    exit(-1);
}
void X86Translator::translate_vcvtps2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtps2pd\n";
    exit(-1);
}
void X86Translator::translate_vcvtps2ph(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtps2ph\n";
    exit(-1);
}
void X86Translator::translate_vcvtps2udq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtps2udq\n";
    exit(-1);
}
void X86Translator::translate_vcvtsd2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtsd2si\n";
    exit(-1);
}
void X86Translator::translate_vcvtsd2usi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtsd2usi\n";
    exit(-1);
}
void X86Translator::translate_vcvtss2si(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtss2si\n";
    exit(-1);
}
void X86Translator::translate_vcvtss2usi(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtss2usi\n";
    exit(-1);
}
void X86Translator::translate_vcvttpd2dqx(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttpd2dqx\n";
    exit(-1);
}
void X86Translator::translate_vcvttpd2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttpd2dq\n";
    exit(-1);
}
void X86Translator::translate_vcvttpd2udq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttpd2udq\n";
    exit(-1);
}
void X86Translator::translate_vcvttps2dq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttps2dq\n";
    exit(-1);
}
void X86Translator::translate_vcvttps2udq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvttps2udq\n";
    exit(-1);
}
void X86Translator::translate_vcvtudq2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtudq2pd\n";
    exit(-1);
}
void X86Translator::translate_vcvtudq2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcvtudq2ps\n";
    exit(-1);
}
void X86Translator::translate_vdivpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdivpd\n";
    exit(-1);
}
void X86Translator::translate_vdivps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdivps\n";
    exit(-1);
}
void X86Translator::translate_vdivsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdivsd\n";
    exit(-1);
}
void X86Translator::translate_vdivss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdivss\n";
    exit(-1);
}
void X86Translator::translate_vdppd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdppd\n";
    exit(-1);
}
void X86Translator::translate_vdpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vdpps\n";
    exit(-1);
}
void X86Translator::translate_verr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction verr\n";
    exit(-1);
}
void X86Translator::translate_verw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction verw\n";
    exit(-1);
}
void X86Translator::translate_vexp2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vexp2pd\n";
    exit(-1);
}
void X86Translator::translate_vexp2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vexp2ps\n";
    exit(-1);
}
void X86Translator::translate_vexpandpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vexpandpd\n";
    exit(-1);
}
void X86Translator::translate_vexpandps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vexpandps\n";
    exit(-1);
}
void X86Translator::translate_vextractf128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextractf128\n";
    exit(-1);
}
void X86Translator::translate_vextractf32x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextractf32x4\n";
    exit(-1);
}
void X86Translator::translate_vextractf64x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextractf64x4\n";
    exit(-1);
}
void X86Translator::translate_vextracti128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextracti128\n";
    exit(-1);
}
void X86Translator::translate_vextracti32x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextracti32x4\n";
    exit(-1);
}
void X86Translator::translate_vextracti64x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextracti64x4\n";
    exit(-1);
}
void X86Translator::translate_vextractps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vextractps\n";
    exit(-1);
}
void X86Translator::translate_vfmadd132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd132pd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd132ps\n";
    exit(-1);
}
void X86Translator::translate_vfmaddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddpd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd213pd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd231pd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddps\n";
    exit(-1);
}
void X86Translator::translate_vfmadd213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd213ps\n";
    exit(-1);
}
void X86Translator::translate_vfmadd231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd231ps\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd213sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd213sd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd132sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd132sd\n";
    exit(-1);
}
void X86Translator::translate_vfmadd231sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd231sd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddss\n";
    exit(-1);
}
void X86Translator::translate_vfmadd213ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd213ss\n";
    exit(-1);
}
void X86Translator::translate_vfmadd132ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd132ss\n";
    exit(-1);
}
void X86Translator::translate_vfmadd231ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmadd231ss\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub132pd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub132ps\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsubpd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub213pd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub231pd\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsubps\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub213ps\n";
    exit(-1);
}
void X86Translator::translate_vfmaddsub231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmaddsub231ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsub132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub132pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub132ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd132pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd132ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubaddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubaddpd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd213pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd231pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubaddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubaddps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd213ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubadd231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubadd231ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubpd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub213pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub231pd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubps\n";
    exit(-1);
}
void X86Translator::translate_vfmsub213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub213ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsub231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub231ps\n";
    exit(-1);
}
void X86Translator::translate_vfmsubsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubsd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub213sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub213sd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub132sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub132sd\n";
    exit(-1);
}
void X86Translator::translate_vfmsub231sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub231sd\n";
    exit(-1);
}
void X86Translator::translate_vfmsubss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsubss\n";
    exit(-1);
}
void X86Translator::translate_vfmsub213ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub213ss\n";
    exit(-1);
}
void X86Translator::translate_vfmsub132ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub132ss\n";
    exit(-1);
}
void X86Translator::translate_vfmsub231ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfmsub231ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd132pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd132ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmaddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmaddpd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd213pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd231pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmaddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmaddps\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd213ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd231ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmaddsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmaddsd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd213sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd213sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd132sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd132sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd231sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd231sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmaddss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmaddss\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd213ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd213ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd132ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd132ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmadd231ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmadd231ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub132pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub132pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub132ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub132ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsubpd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub213pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub213pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub231pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub231pd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsubps\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub213ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub213ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub231ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub231ps\n";
    exit(-1);
}
void X86Translator::translate_vfnmsubsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsubsd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub213sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub213sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub132sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub132sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub231sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub231sd\n";
    exit(-1);
}
void X86Translator::translate_vfnmsubss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsubss\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub213ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub213ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub132ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub132ss\n";
    exit(-1);
}
void X86Translator::translate_vfnmsub231ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfnmsub231ss\n";
    exit(-1);
}
void X86Translator::translate_vfrczpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfrczpd\n";
    exit(-1);
}
void X86Translator::translate_vfrczps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfrczps\n";
    exit(-1);
}
void X86Translator::translate_vfrczsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfrczsd\n";
    exit(-1);
}
void X86Translator::translate_vfrczss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vfrczss\n";
    exit(-1);
}
void X86Translator::translate_vorpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vorpd\n";
    exit(-1);
}
void X86Translator::translate_vorps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vorps\n";
    exit(-1);
}
void X86Translator::translate_vxorpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vxorpd\n";
    exit(-1);
}
void X86Translator::translate_vxorps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vxorps\n";
    exit(-1);
}
void X86Translator::translate_vgatherdpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherdpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherdps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherdps\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf0dpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf0dpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf0dps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf0dps\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf0qpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf0qpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf0qps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf0qps\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf1dpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf1dpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf1dps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf1dps\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf1qpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf1qpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherpf1qps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherpf1qps\n";
    exit(-1);
}
void X86Translator::translate_vgatherqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherqpd\n";
    exit(-1);
}
void X86Translator::translate_vgatherqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vgatherqps\n";
    exit(-1);
}
void X86Translator::translate_vhaddpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vhaddpd\n";
    exit(-1);
}
void X86Translator::translate_vhaddps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vhaddps\n";
    exit(-1);
}
void X86Translator::translate_vhsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vhsubpd\n";
    exit(-1);
}
void X86Translator::translate_vhsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vhsubps\n";
    exit(-1);
}
void X86Translator::translate_vinsertf128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertf128\n";
    exit(-1);
}
void X86Translator::translate_vinsertf32x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertf32x4\n";
    exit(-1);
}
void X86Translator::translate_vinsertf32x8(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertf32x8\n";
    exit(-1);
}
void X86Translator::translate_vinsertf64x2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertf64x2\n";
    exit(-1);
}
void X86Translator::translate_vinsertf64x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertf64x4\n";
    exit(-1);
}
void X86Translator::translate_vinserti128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinserti128\n";
    exit(-1);
}
void X86Translator::translate_vinserti32x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinserti32x4\n";
    exit(-1);
}
void X86Translator::translate_vinserti32x8(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinserti32x8\n";
    exit(-1);
}
void X86Translator::translate_vinserti64x2(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinserti64x2\n";
    exit(-1);
}
void X86Translator::translate_vinserti64x4(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinserti64x4\n";
    exit(-1);
}
void X86Translator::translate_vinsertps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vinsertps\n";
    exit(-1);
}
void X86Translator::translate_vlddqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vlddqu\n";
    exit(-1);
}
void X86Translator::translate_vldmxcsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vldmxcsr\n";
    exit(-1);
}
void X86Translator::translate_vmaskmovdqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaskmovdqu\n";
    exit(-1);
}
void X86Translator::translate_vmaskmovpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaskmovpd\n";
    exit(-1);
}
void X86Translator::translate_vmaskmovps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaskmovps\n";
    exit(-1);
}
void X86Translator::translate_vmaxpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaxpd\n";
    exit(-1);
}
void X86Translator::translate_vmaxps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaxps\n";
    exit(-1);
}
void X86Translator::translate_vmaxsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaxsd\n";
    exit(-1);
}
void X86Translator::translate_vmaxss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmaxss\n";
    exit(-1);
}
void X86Translator::translate_vmcall(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmcall\n";
    exit(-1);
}
void X86Translator::translate_vmclear(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmclear\n";
    exit(-1);
}
void X86Translator::translate_vmfunc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmfunc\n";
    exit(-1);
}
void X86Translator::translate_vminpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vminpd\n";
    exit(-1);
}
void X86Translator::translate_vminps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vminps\n";
    exit(-1);
}
void X86Translator::translate_vminsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vminsd\n";
    exit(-1);
}
void X86Translator::translate_vminss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vminss\n";
    exit(-1);
}
void X86Translator::translate_vmlaunch(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmlaunch\n";
    exit(-1);
}
void X86Translator::translate_vmload(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmload\n";
    exit(-1);
}
void X86Translator::translate_vmmcall(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmmcall\n";
    exit(-1);
}
void X86Translator::translate_vmovq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovq\n";
    exit(-1);
}
void X86Translator::translate_vmovddup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovddup\n";
    exit(-1);
}
void X86Translator::translate_vmovd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovd\n";
    exit(-1);
}
void X86Translator::translate_vmovdqa32(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqa32\n";
    exit(-1);
}
void X86Translator::translate_vmovdqa64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqa64\n";
    exit(-1);
}
void X86Translator::translate_vmovdqa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqa\n";
    exit(-1);
}
void X86Translator::translate_vmovdqu16(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqu16\n";
    exit(-1);
}
void X86Translator::translate_vmovdqu32(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqu32\n";
    exit(-1);
}
void X86Translator::translate_vmovdqu64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqu64\n";
    exit(-1);
}
void X86Translator::translate_vmovdqu8(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqu8\n";
    exit(-1);
}
void X86Translator::translate_vmovdqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovdqu\n";
    exit(-1);
}
void X86Translator::translate_vmovhlps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovhlps\n";
    exit(-1);
}
void X86Translator::translate_vmovhpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovhpd\n";
    exit(-1);
}
void X86Translator::translate_vmovhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovhps\n";
    exit(-1);
}
void X86Translator::translate_vmovlhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovlhps\n";
    exit(-1);
}
void X86Translator::translate_vmovlpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovlpd\n";
    exit(-1);
}
void X86Translator::translate_vmovlps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovlps\n";
    exit(-1);
}
void X86Translator::translate_vmovmskpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovmskpd\n";
    exit(-1);
}
void X86Translator::translate_vmovmskps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovmskps\n";
    exit(-1);
}
void X86Translator::translate_vmovntdqa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovntdqa\n";
    exit(-1);
}
void X86Translator::translate_vmovntdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovntdq\n";
    exit(-1);
}
void X86Translator::translate_vmovntpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovntpd\n";
    exit(-1);
}
void X86Translator::translate_vmovntps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovntps\n";
    exit(-1);
}
void X86Translator::translate_vmovsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovsd\n";
    exit(-1);
}
void X86Translator::translate_vmovshdup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovshdup\n";
    exit(-1);
}
void X86Translator::translate_vmovsldup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovsldup\n";
    exit(-1);
}
void X86Translator::translate_vmovss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovss\n";
    exit(-1);
}
void X86Translator::translate_vmovupd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovupd\n";
    exit(-1);
}
void X86Translator::translate_vmovups(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmovups\n";
    exit(-1);
}
void X86Translator::translate_vmpsadbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmpsadbw\n";
    exit(-1);
}
void X86Translator::translate_vmptrld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmptrld\n";
    exit(-1);
}
void X86Translator::translate_vmptrst(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmptrst\n";
    exit(-1);
}
void X86Translator::translate_vmread(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmread\n";
    exit(-1);
}
void X86Translator::translate_vmresume(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmresume\n";
    exit(-1);
}
void X86Translator::translate_vmrun(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmrun\n";
    exit(-1);
}
void X86Translator::translate_vmsave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmsave\n";
    exit(-1);
}
void X86Translator::translate_vmulpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmulpd\n";
    exit(-1);
}
void X86Translator::translate_vmulps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmulps\n";
    exit(-1);
}
void X86Translator::translate_vmulsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmulsd\n";
    exit(-1);
}
void X86Translator::translate_vmulss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmulss\n";
    exit(-1);
}
void X86Translator::translate_vmwrite(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmwrite\n";
    exit(-1);
}
void X86Translator::translate_vmxoff(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmxoff\n";
    exit(-1);
}
void X86Translator::translate_vmxon(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vmxon\n";
    exit(-1);
}
void X86Translator::translate_vpabsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpabsb\n";
    exit(-1);
}
void X86Translator::translate_vpabsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpabsd\n";
    exit(-1);
}
void X86Translator::translate_vpabsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpabsq\n";
    exit(-1);
}
void X86Translator::translate_vpabsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpabsw\n";
    exit(-1);
}
void X86Translator::translate_vpackssdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpackssdw\n";
    exit(-1);
}
void X86Translator::translate_vpacksswb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpacksswb\n";
    exit(-1);
}
void X86Translator::translate_vpackusdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpackusdw\n";
    exit(-1);
}
void X86Translator::translate_vpackuswb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpackuswb\n";
    exit(-1);
}
void X86Translator::translate_vpaddb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddb\n";
    exit(-1);
}
void X86Translator::translate_vpaddd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddd\n";
    exit(-1);
}
void X86Translator::translate_vpaddq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddq\n";
    exit(-1);
}
void X86Translator::translate_vpaddsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddsb\n";
    exit(-1);
}
void X86Translator::translate_vpaddsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddsw\n";
    exit(-1);
}
void X86Translator::translate_vpaddusb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddusb\n";
    exit(-1);
}
void X86Translator::translate_vpaddusw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddusw\n";
    exit(-1);
}
void X86Translator::translate_vpaddw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpaddw\n";
    exit(-1);
}
void X86Translator::translate_vpalignr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpalignr\n";
    exit(-1);
}
void X86Translator::translate_vpandd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpandd\n";
    exit(-1);
}
void X86Translator::translate_vpandnd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpandnd\n";
    exit(-1);
}
void X86Translator::translate_vpandnq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpandnq\n";
    exit(-1);
}
void X86Translator::translate_vpandn(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpandn\n";
    exit(-1);
}
void X86Translator::translate_vpandq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpandq\n";
    exit(-1);
}
void X86Translator::translate_vpand(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpand\n";
    exit(-1);
}
void X86Translator::translate_vpavgb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpavgb\n";
    exit(-1);
}
void X86Translator::translate_vpavgw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpavgw\n";
    exit(-1);
}
void X86Translator::translate_vpblendd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendd\n";
    exit(-1);
}
void X86Translator::translate_vpblendmb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendmb\n";
    exit(-1);
}
void X86Translator::translate_vpblendmd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendmd\n";
    exit(-1);
}
void X86Translator::translate_vpblendmq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendmq\n";
    exit(-1);
}
void X86Translator::translate_vpblendmw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendmw\n";
    exit(-1);
}
void X86Translator::translate_vpblendvb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendvb\n";
    exit(-1);
}
void X86Translator::translate_vpblendw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpblendw\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastb\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastd\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastmb2q(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastmb2q\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastmw2d(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastmw2d\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastq\n";
    exit(-1);
}
void X86Translator::translate_vpbroadcastw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpbroadcastw\n";
    exit(-1);
}
void X86Translator::translate_vpclmulqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpclmulqdq\n";
    exit(-1);
}
void X86Translator::translate_vpcmov(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmov\n";
    exit(-1);
}
void X86Translator::translate_vpcmpb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpb\n";
    exit(-1);
}
void X86Translator::translate_vpcmpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpd\n";
    exit(-1);
}
void X86Translator::translate_vpcmpeqb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpeqb\n";
    exit(-1);
}
void X86Translator::translate_vpcmpeqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpeqd\n";
    exit(-1);
}
void X86Translator::translate_vpcmpeqq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpeqq\n";
    exit(-1);
}
void X86Translator::translate_vpcmpeqw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpeqw\n";
    exit(-1);
}
void X86Translator::translate_vpcmpestri(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpestri\n";
    exit(-1);
}
void X86Translator::translate_vpcmpestrm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpestrm\n";
    exit(-1);
}
void X86Translator::translate_vpcmpgtb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpgtb\n";
    exit(-1);
}
void X86Translator::translate_vpcmpgtd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpgtd\n";
    exit(-1);
}
void X86Translator::translate_vpcmpgtq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpgtq\n";
    exit(-1);
}
void X86Translator::translate_vpcmpgtw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpgtw\n";
    exit(-1);
}
void X86Translator::translate_vpcmpistri(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpistri\n";
    exit(-1);
}
void X86Translator::translate_vpcmpistrm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpistrm\n";
    exit(-1);
}
void X86Translator::translate_vpcmpq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpq\n";
    exit(-1);
}
void X86Translator::translate_vpcmpub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpub\n";
    exit(-1);
}
void X86Translator::translate_vpcmpud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpud\n";
    exit(-1);
}
void X86Translator::translate_vpcmpuq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpuq\n";
    exit(-1);
}
void X86Translator::translate_vpcmpuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpuw\n";
    exit(-1);
}
void X86Translator::translate_vpcmpw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcmpw\n";
    exit(-1);
}
void X86Translator::translate_vpcomb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomb\n";
    exit(-1);
}
void X86Translator::translate_vpcomd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomd\n";
    exit(-1);
}
void X86Translator::translate_vpcompressd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcompressd\n";
    exit(-1);
}
void X86Translator::translate_vpcompressq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcompressq\n";
    exit(-1);
}
void X86Translator::translate_vpcomq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomq\n";
    exit(-1);
}
void X86Translator::translate_vpcomub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomub\n";
    exit(-1);
}
void X86Translator::translate_vpcomud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomud\n";
    exit(-1);
}
void X86Translator::translate_vpcomuq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomuq\n";
    exit(-1);
}
void X86Translator::translate_vpcomuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomuw\n";
    exit(-1);
}
void X86Translator::translate_vpcomw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpcomw\n";
    exit(-1);
}
void X86Translator::translate_vpconflictd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpconflictd\n";
    exit(-1);
}
void X86Translator::translate_vpconflictq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpconflictq\n";
    exit(-1);
}
void X86Translator::translate_vperm2f128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vperm2f128\n";
    exit(-1);
}
void X86Translator::translate_vperm2i128(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vperm2i128\n";
    exit(-1);
}
void X86Translator::translate_vpermd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermd\n";
    exit(-1);
}
void X86Translator::translate_vpermi2d(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermi2d\n";
    exit(-1);
}
void X86Translator::translate_vpermi2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermi2pd\n";
    exit(-1);
}
void X86Translator::translate_vpermi2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermi2ps\n";
    exit(-1);
}
void X86Translator::translate_vpermi2q(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermi2q\n";
    exit(-1);
}
void X86Translator::translate_vpermil2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermil2pd\n";
    exit(-1);
}
void X86Translator::translate_vpermil2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermil2ps\n";
    exit(-1);
}
void X86Translator::translate_vpermilpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermilpd\n";
    exit(-1);
}
void X86Translator::translate_vpermilps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermilps\n";
    exit(-1);
}
void X86Translator::translate_vpermpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermpd\n";
    exit(-1);
}
void X86Translator::translate_vpermps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermps\n";
    exit(-1);
}
void X86Translator::translate_vpermq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermq\n";
    exit(-1);
}
void X86Translator::translate_vpermt2d(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermt2d\n";
    exit(-1);
}
void X86Translator::translate_vpermt2pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermt2pd\n";
    exit(-1);
}
void X86Translator::translate_vpermt2ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermt2ps\n";
    exit(-1);
}
void X86Translator::translate_vpermt2q(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpermt2q\n";
    exit(-1);
}
void X86Translator::translate_vpexpandd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpexpandd\n";
    exit(-1);
}
void X86Translator::translate_vpexpandq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpexpandq\n";
    exit(-1);
}
void X86Translator::translate_vpextrb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpextrb\n";
    exit(-1);
}
void X86Translator::translate_vpextrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpextrd\n";
    exit(-1);
}
void X86Translator::translate_vpextrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpextrq\n";
    exit(-1);
}
void X86Translator::translate_vpextrw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpextrw\n";
    exit(-1);
}
void X86Translator::translate_vpgatherdd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpgatherdd\n";
    exit(-1);
}
void X86Translator::translate_vpgatherdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpgatherdq\n";
    exit(-1);
}
void X86Translator::translate_vpgatherqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpgatherqd\n";
    exit(-1);
}
void X86Translator::translate_vpgatherqq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpgatherqq\n";
    exit(-1);
}
void X86Translator::translate_vphaddbd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddbd\n";
    exit(-1);
}
void X86Translator::translate_vphaddbq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddbq\n";
    exit(-1);
}
void X86Translator::translate_vphaddbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddbw\n";
    exit(-1);
}
void X86Translator::translate_vphadddq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphadddq\n";
    exit(-1);
}
void X86Translator::translate_vphaddd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddd\n";
    exit(-1);
}
void X86Translator::translate_vphaddsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddsw\n";
    exit(-1);
}
void X86Translator::translate_vphaddubd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddubd\n";
    exit(-1);
}
void X86Translator::translate_vphaddubq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddubq\n";
    exit(-1);
}
void X86Translator::translate_vphaddubw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddubw\n";
    exit(-1);
}
void X86Translator::translate_vphaddudq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddudq\n";
    exit(-1);
}
void X86Translator::translate_vphadduwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphadduwd\n";
    exit(-1);
}
void X86Translator::translate_vphadduwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphadduwq\n";
    exit(-1);
}
void X86Translator::translate_vphaddwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddwd\n";
    exit(-1);
}
void X86Translator::translate_vphaddwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddwq\n";
    exit(-1);
}
void X86Translator::translate_vphaddw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphaddw\n";
    exit(-1);
}
void X86Translator::translate_vphminposuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphminposuw\n";
    exit(-1);
}
void X86Translator::translate_vphsubbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubbw\n";
    exit(-1);
}
void X86Translator::translate_vphsubdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubdq\n";
    exit(-1);
}
void X86Translator::translate_vphsubd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubd\n";
    exit(-1);
}
void X86Translator::translate_vphsubsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubsw\n";
    exit(-1);
}
void X86Translator::translate_vphsubwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubwd\n";
    exit(-1);
}
void X86Translator::translate_vphsubw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vphsubw\n";
    exit(-1);
}
void X86Translator::translate_vpinsrb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpinsrb\n";
    exit(-1);
}
void X86Translator::translate_vpinsrd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpinsrd\n";
    exit(-1);
}
void X86Translator::translate_vpinsrq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpinsrq\n";
    exit(-1);
}
void X86Translator::translate_vpinsrw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpinsrw\n";
    exit(-1);
}
void X86Translator::translate_vplzcntd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vplzcntd\n";
    exit(-1);
}
void X86Translator::translate_vplzcntq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vplzcntq\n";
    exit(-1);
}
void X86Translator::translate_vpmacsdd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacsdd\n";
    exit(-1);
}
void X86Translator::translate_vpmacsdqh(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacsdqh\n";
    exit(-1);
}
void X86Translator::translate_vpmacsdql(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacsdql\n";
    exit(-1);
}
void X86Translator::translate_vpmacssdd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacssdd\n";
    exit(-1);
}
void X86Translator::translate_vpmacssdqh(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacssdqh\n";
    exit(-1);
}
void X86Translator::translate_vpmacssdql(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacssdql\n";
    exit(-1);
}
void X86Translator::translate_vpmacsswd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacsswd\n";
    exit(-1);
}
void X86Translator::translate_vpmacssww(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacssww\n";
    exit(-1);
}
void X86Translator::translate_vpmacswd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacswd\n";
    exit(-1);
}
void X86Translator::translate_vpmacsww(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmacsww\n";
    exit(-1);
}
void X86Translator::translate_vpmadcsswd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmadcsswd\n";
    exit(-1);
}
void X86Translator::translate_vpmadcswd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmadcswd\n";
    exit(-1);
}
void X86Translator::translate_vpmaddubsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaddubsw\n";
    exit(-1);
}
void X86Translator::translate_vpmaddwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaddwd\n";
    exit(-1);
}
void X86Translator::translate_vpmaskmovd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaskmovd\n";
    exit(-1);
}
void X86Translator::translate_vpmaskmovq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaskmovq\n";
    exit(-1);
}
void X86Translator::translate_vpmaxsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxsb\n";
    exit(-1);
}
void X86Translator::translate_vpmaxsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxsd\n";
    exit(-1);
}
void X86Translator::translate_vpmaxsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxsq\n";
    exit(-1);
}
void X86Translator::translate_vpmaxsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxsw\n";
    exit(-1);
}
void X86Translator::translate_vpmaxub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxub\n";
    exit(-1);
}
void X86Translator::translate_vpmaxud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxud\n";
    exit(-1);
}
void X86Translator::translate_vpmaxuq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxuq\n";
    exit(-1);
}
void X86Translator::translate_vpmaxuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmaxuw\n";
    exit(-1);
}
void X86Translator::translate_vpminsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminsb\n";
    exit(-1);
}
void X86Translator::translate_vpminsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminsd\n";
    exit(-1);
}
void X86Translator::translate_vpminsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminsq\n";
    exit(-1);
}
void X86Translator::translate_vpminsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminsw\n";
    exit(-1);
}
void X86Translator::translate_vpminub(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminub\n";
    exit(-1);
}
void X86Translator::translate_vpminud(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminud\n";
    exit(-1);
}
void X86Translator::translate_vpminuq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminuq\n";
    exit(-1);
}
void X86Translator::translate_vpminuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpminuw\n";
    exit(-1);
}
void X86Translator::translate_vpmovdb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovdb\n";
    exit(-1);
}
void X86Translator::translate_vpmovdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovdw\n";
    exit(-1);
}
void X86Translator::translate_vpmovm2b(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovm2b\n";
    exit(-1);
}
void X86Translator::translate_vpmovm2d(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovm2d\n";
    exit(-1);
}
void X86Translator::translate_vpmovm2q(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovm2q\n";
    exit(-1);
}
void X86Translator::translate_vpmovm2w(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovm2w\n";
    exit(-1);
}
void X86Translator::translate_vpmovmskb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovmskb\n";
    exit(-1);
}
void X86Translator::translate_vpmovqb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovqb\n";
    exit(-1);
}
void X86Translator::translate_vpmovqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovqd\n";
    exit(-1);
}
void X86Translator::translate_vpmovqw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovqw\n";
    exit(-1);
}
void X86Translator::translate_vpmovsdb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsdb\n";
    exit(-1);
}
void X86Translator::translate_vpmovsdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsdw\n";
    exit(-1);
}
void X86Translator::translate_vpmovsqb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsqb\n";
    exit(-1);
}
void X86Translator::translate_vpmovsqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsqd\n";
    exit(-1);
}
void X86Translator::translate_vpmovsqw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsqw\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxbd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxbd\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxbq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxbq\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxbw\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxdq\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxwd\n";
    exit(-1);
}
void X86Translator::translate_vpmovsxwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovsxwq\n";
    exit(-1);
}
void X86Translator::translate_vpmovusdb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovusdb\n";
    exit(-1);
}
void X86Translator::translate_vpmovusdw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovusdw\n";
    exit(-1);
}
void X86Translator::translate_vpmovusqb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovusqb\n";
    exit(-1);
}
void X86Translator::translate_vpmovusqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovusqd\n";
    exit(-1);
}
void X86Translator::translate_vpmovusqw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovusqw\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxbd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxbd\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxbq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxbq\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxbw\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxdq\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxwd\n";
    exit(-1);
}
void X86Translator::translate_vpmovzxwq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmovzxwq\n";
    exit(-1);
}
void X86Translator::translate_vpmuldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmuldq\n";
    exit(-1);
}
void X86Translator::translate_vpmulhrsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmulhrsw\n";
    exit(-1);
}
void X86Translator::translate_vpmulhuw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmulhuw\n";
    exit(-1);
}
void X86Translator::translate_vpmulhw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmulhw\n";
    exit(-1);
}
void X86Translator::translate_vpmulld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmulld\n";
    exit(-1);
}
void X86Translator::translate_vpmullq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmullq\n";
    exit(-1);
}
void X86Translator::translate_vpmullw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmullw\n";
    exit(-1);
}
void X86Translator::translate_vpmuludq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpmuludq\n";
    exit(-1);
}
void X86Translator::translate_vpord(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpord\n";
    exit(-1);
}
void X86Translator::translate_vporq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vporq\n";
    exit(-1);
}
void X86Translator::translate_vpor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpor\n";
    exit(-1);
}
void X86Translator::translate_vpperm(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpperm\n";
    exit(-1);
}
void X86Translator::translate_vprotb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vprotb\n";
    exit(-1);
}
void X86Translator::translate_vprotd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vprotd\n";
    exit(-1);
}
void X86Translator::translate_vprotq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vprotq\n";
    exit(-1);
}
void X86Translator::translate_vprotw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vprotw\n";
    exit(-1);
}
void X86Translator::translate_vpsadbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsadbw\n";
    exit(-1);
}
void X86Translator::translate_vpscatterdd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpscatterdd\n";
    exit(-1);
}
void X86Translator::translate_vpscatterdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpscatterdq\n";
    exit(-1);
}
void X86Translator::translate_vpscatterqd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpscatterqd\n";
    exit(-1);
}
void X86Translator::translate_vpscatterqq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpscatterqq\n";
    exit(-1);
}
void X86Translator::translate_vpshab(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshab\n";
    exit(-1);
}
void X86Translator::translate_vpshad(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshad\n";
    exit(-1);
}
void X86Translator::translate_vpshaq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshaq\n";
    exit(-1);
}
void X86Translator::translate_vpshaw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshaw\n";
    exit(-1);
}
void X86Translator::translate_vpshlb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshlb\n";
    exit(-1);
}
void X86Translator::translate_vpshld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshld\n";
    exit(-1);
}
void X86Translator::translate_vpshlq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshlq\n";
    exit(-1);
}
void X86Translator::translate_vpshlw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshlw\n";
    exit(-1);
}
void X86Translator::translate_vpshufb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshufb\n";
    exit(-1);
}
void X86Translator::translate_vpshufd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshufd\n";
    exit(-1);
}
void X86Translator::translate_vpshufhw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshufhw\n";
    exit(-1);
}
void X86Translator::translate_vpshuflw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpshuflw\n";
    exit(-1);
}
void X86Translator::translate_vpsignb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsignb\n";
    exit(-1);
}
void X86Translator::translate_vpsignd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsignd\n";
    exit(-1);
}
void X86Translator::translate_vpsignw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsignw\n";
    exit(-1);
}
void X86Translator::translate_vpslldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpslldq\n";
    exit(-1);
}
void X86Translator::translate_vpslld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpslld\n";
    exit(-1);
}
void X86Translator::translate_vpsllq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsllq\n";
    exit(-1);
}
void X86Translator::translate_vpsllvd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsllvd\n";
    exit(-1);
}
void X86Translator::translate_vpsllvq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsllvq\n";
    exit(-1);
}
void X86Translator::translate_vpsllw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsllw\n";
    exit(-1);
}
void X86Translator::translate_vpsrad(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrad\n";
    exit(-1);
}
void X86Translator::translate_vpsraq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsraq\n";
    exit(-1);
}
void X86Translator::translate_vpsravd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsravd\n";
    exit(-1);
}
void X86Translator::translate_vpsravq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsravq\n";
    exit(-1);
}
void X86Translator::translate_vpsraw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsraw\n";
    exit(-1);
}
void X86Translator::translate_vpsrldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrldq\n";
    exit(-1);
}
void X86Translator::translate_vpsrld(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrld\n";
    exit(-1);
}
void X86Translator::translate_vpsrlq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrlq\n";
    exit(-1);
}
void X86Translator::translate_vpsrlvd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrlvd\n";
    exit(-1);
}
void X86Translator::translate_vpsrlvq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrlvq\n";
    exit(-1);
}
void X86Translator::translate_vpsrlw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsrlw\n";
    exit(-1);
}
void X86Translator::translate_vpsubb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubb\n";
    exit(-1);
}
void X86Translator::translate_vpsubd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubd\n";
    exit(-1);
}
void X86Translator::translate_vpsubq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubq\n";
    exit(-1);
}
void X86Translator::translate_vpsubsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubsb\n";
    exit(-1);
}
void X86Translator::translate_vpsubsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubsw\n";
    exit(-1);
}
void X86Translator::translate_vpsubusb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubusb\n";
    exit(-1);
}
void X86Translator::translate_vpsubusw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubusw\n";
    exit(-1);
}
void X86Translator::translate_vpsubw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpsubw\n";
    exit(-1);
}
void X86Translator::translate_vptestmd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vptestmd\n";
    exit(-1);
}
void X86Translator::translate_vptestmq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vptestmq\n";
    exit(-1);
}
void X86Translator::translate_vptestnmd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vptestnmd\n";
    exit(-1);
}
void X86Translator::translate_vptestnmq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vptestnmq\n";
    exit(-1);
}
void X86Translator::translate_vptest(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vptest\n";
    exit(-1);
}
void X86Translator::translate_vpunpckhbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpckhbw\n";
    exit(-1);
}
void X86Translator::translate_vpunpckhdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpckhdq\n";
    exit(-1);
}
void X86Translator::translate_vpunpckhqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpckhqdq\n";
    exit(-1);
}
void X86Translator::translate_vpunpckhwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpckhwd\n";
    exit(-1);
}
void X86Translator::translate_vpunpcklbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpcklbw\n";
    exit(-1);
}
void X86Translator::translate_vpunpckldq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpckldq\n";
    exit(-1);
}
void X86Translator::translate_vpunpcklqdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpcklqdq\n";
    exit(-1);
}
void X86Translator::translate_vpunpcklwd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpunpcklwd\n";
    exit(-1);
}
void X86Translator::translate_vpxord(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpxord\n";
    exit(-1);
}
void X86Translator::translate_vpxorq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpxorq\n";
    exit(-1);
}
void X86Translator::translate_vpxor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vpxor\n";
    exit(-1);
}
void X86Translator::translate_vrcp14pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp14pd\n";
    exit(-1);
}
void X86Translator::translate_vrcp14ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp14ps\n";
    exit(-1);
}
void X86Translator::translate_vrcp14sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp14sd\n";
    exit(-1);
}
void X86Translator::translate_vrcp14ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp14ss\n";
    exit(-1);
}
void X86Translator::translate_vrcp28pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp28pd\n";
    exit(-1);
}
void X86Translator::translate_vrcp28ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp28ps\n";
    exit(-1);
}
void X86Translator::translate_vrcp28sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp28sd\n";
    exit(-1);
}
void X86Translator::translate_vrcp28ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcp28ss\n";
    exit(-1);
}
void X86Translator::translate_vrcpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcpps\n";
    exit(-1);
}
void X86Translator::translate_vrcpss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrcpss\n";
    exit(-1);
}
void X86Translator::translate_vrndscalepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrndscalepd\n";
    exit(-1);
}
void X86Translator::translate_vrndscaleps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrndscaleps\n";
    exit(-1);
}
void X86Translator::translate_vrndscalesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrndscalesd\n";
    exit(-1);
}
void X86Translator::translate_vrndscaless(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrndscaless\n";
    exit(-1);
}
void X86Translator::translate_vroundpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vroundpd\n";
    exit(-1);
}
void X86Translator::translate_vroundps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vroundps\n";
    exit(-1);
}
void X86Translator::translate_vroundsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vroundsd\n";
    exit(-1);
}
void X86Translator::translate_vroundss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vroundss\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt14pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt14pd\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt14ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt14ps\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt14sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt14sd\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt14ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt14ss\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt28pd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt28pd\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt28ps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt28ps\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt28sd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt28sd\n";
    exit(-1);
}
void X86Translator::translate_vrsqrt28ss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrt28ss\n";
    exit(-1);
}
void X86Translator::translate_vrsqrtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrtps\n";
    exit(-1);
}
void X86Translator::translate_vrsqrtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vrsqrtss\n";
    exit(-1);
}
void X86Translator::translate_vscatterdpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterdpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterdps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterdps\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf0dpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf0dpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf0dps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf0dps\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf0qpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf0qpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf0qps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf0qps\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf1dpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf1dpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf1dps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf1dps\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf1qpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf1qpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterpf1qps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterpf1qps\n";
    exit(-1);
}
void X86Translator::translate_vscatterqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterqpd\n";
    exit(-1);
}
void X86Translator::translate_vscatterqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vscatterqps\n";
    exit(-1);
}
void X86Translator::translate_vshufpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vshufpd\n";
    exit(-1);
}
void X86Translator::translate_vshufps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vshufps\n";
    exit(-1);
}
void X86Translator::translate_vsqrtpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsqrtpd\n";
    exit(-1);
}
void X86Translator::translate_vsqrtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsqrtps\n";
    exit(-1);
}
void X86Translator::translate_vsqrtsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsqrtsd\n";
    exit(-1);
}
void X86Translator::translate_vsqrtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsqrtss\n";
    exit(-1);
}
void X86Translator::translate_vstmxcsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vstmxcsr\n";
    exit(-1);
}
void X86Translator::translate_vsubpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsubpd\n";
    exit(-1);
}
void X86Translator::translate_vsubps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsubps\n";
    exit(-1);
}
void X86Translator::translate_vsubsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsubsd\n";
    exit(-1);
}
void X86Translator::translate_vsubss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vsubss\n";
    exit(-1);
}
void X86Translator::translate_vtestpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vtestpd\n";
    exit(-1);
}
void X86Translator::translate_vtestps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vtestps\n";
    exit(-1);
}
void X86Translator::translate_vunpckhpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vunpckhpd\n";
    exit(-1);
}
void X86Translator::translate_vunpckhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vunpckhps\n";
    exit(-1);
}
void X86Translator::translate_vunpcklpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vunpcklpd\n";
    exit(-1);
}
void X86Translator::translate_vunpcklps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vunpcklps\n";
    exit(-1);
}
void X86Translator::translate_vzeroall(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vzeroall\n";
    exit(-1);
}
void X86Translator::translate_vzeroupper(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vzeroupper\n";
    exit(-1);
}
void X86Translator::translate_wait(GuestInst *Inst) {
    dbgs() << "Untranslated instruction wait\n";
    exit(-1);
}
void X86Translator::translate_wbinvd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction wbinvd\n";
    exit(-1);
}
void X86Translator::translate_wrfsbase(GuestInst *Inst) {
    dbgs() << "Untranslated instruction wrfsbase\n";
    exit(-1);
}
void X86Translator::translate_wrgsbase(GuestInst *Inst) {
    dbgs() << "Untranslated instruction wrgsbase\n";
    exit(-1);
}
void X86Translator::translate_wrmsr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction wrmsr\n";
    exit(-1);
}
void X86Translator::translate_xabort(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xabort\n";
    exit(-1);
}
void X86Translator::translate_xacquire(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xacquire\n";
    exit(-1);
}
void X86Translator::translate_xbegin(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xbegin\n";
    exit(-1);
}
void X86Translator::translate_xchg(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xchg\n";
    exit(-1);
}
void X86Translator::translate_xcryptcbc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xcryptcbc\n";
    exit(-1);
}
void X86Translator::translate_xcryptcfb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xcryptcfb\n";
    exit(-1);
}
void X86Translator::translate_xcryptctr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xcryptctr\n";
    exit(-1);
}
void X86Translator::translate_xcryptecb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xcryptecb\n";
    exit(-1);
}
void X86Translator::translate_xcryptofb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xcryptofb\n";
    exit(-1);
}
void X86Translator::translate_xend(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xend\n";
    exit(-1);
}
void X86Translator::translate_xgetbv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xgetbv\n";
    exit(-1);
}
void X86Translator::translate_xlatb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xlatb\n";
    exit(-1);
}
void X86Translator::translate_xrelease(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xrelease\n";
    exit(-1);
}
void X86Translator::translate_xrstor(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xrstor\n";
    exit(-1);
}
void X86Translator::translate_xrstor64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xrstor64\n";
    exit(-1);
}
void X86Translator::translate_xrstors(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xrstors\n";
    exit(-1);
}
void X86Translator::translate_xrstors64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xrstors64\n";
    exit(-1);
}
void X86Translator::translate_xsave(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsave\n";
    exit(-1);
}
void X86Translator::translate_xsave64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsave64\n";
    exit(-1);
}
void X86Translator::translate_xsavec(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsavec\n";
    exit(-1);
}
void X86Translator::translate_xsavec64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsavec64\n";
    exit(-1);
}
void X86Translator::translate_xsaveopt(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsaveopt\n";
    exit(-1);
}
void X86Translator::translate_xsaveopt64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsaveopt64\n";
    exit(-1);
}
void X86Translator::translate_xsaves(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsaves\n";
    exit(-1);
}
void X86Translator::translate_xsaves64(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsaves64\n";
    exit(-1);
}
void X86Translator::translate_xsetbv(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsetbv\n";
    exit(-1);
}
void X86Translator::translate_xsha1(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsha1\n";
    exit(-1);
}
void X86Translator::translate_xsha256(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xsha256\n";
    exit(-1);
}
void X86Translator::translate_xstore(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xstore\n";
    exit(-1);
}
void X86Translator::translate_xtest(GuestInst *Inst) {
    dbgs() << "Untranslated instruction xtest\n";
    exit(-1);
}
void X86Translator::translate_fdisi8087_nop(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fdisi8087_nop\n";
    exit(-1);
}
void X86Translator::translate_feni8087_nop(GuestInst *Inst) {
    dbgs() << "Untranslated instruction feni8087_nop\n";
    exit(-1);
}
void X86Translator::translate_cmpss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpss\n";
    exit(-1);
}
void X86Translator::translate_cmpeqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpeqss\n";
    exit(-1);
}
void X86Translator::translate_cmpltss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpltss\n";
    exit(-1);
}
void X86Translator::translate_cmpless(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpless\n";
    exit(-1);
}
void X86Translator::translate_cmpunordss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpunordss\n";
    exit(-1);
}
void X86Translator::translate_cmpneqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpneqss\n";
    exit(-1);
}
void X86Translator::translate_cmpnltss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnltss\n";
    exit(-1);
}
void X86Translator::translate_cmpnless(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnless\n";
    exit(-1);
}
void X86Translator::translate_cmpordss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpordss\n";
    exit(-1);
}
void X86Translator::translate_cmpsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpsd\n";
    exit(-1);
}
void X86Translator::translate_cmpeqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpeqsd\n";
    exit(-1);
}
void X86Translator::translate_cmpltsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpltsd\n";
    exit(-1);
}
void X86Translator::translate_cmplesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmplesd\n";
    exit(-1);
}
void X86Translator::translate_cmpunordsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpunordsd\n";
    exit(-1);
}
void X86Translator::translate_cmpneqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpneqsd\n";
    exit(-1);
}
void X86Translator::translate_cmpnltsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnltsd\n";
    exit(-1);
}
void X86Translator::translate_cmpnlesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnlesd\n";
    exit(-1);
}
void X86Translator::translate_cmpordsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpordsd\n";
    exit(-1);
}
void X86Translator::translate_cmpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpps\n";
    exit(-1);
}
void X86Translator::translate_cmpeqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpeqps\n";
    exit(-1);
}
void X86Translator::translate_cmpltps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpltps\n";
    exit(-1);
}
void X86Translator::translate_cmpleps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpleps\n";
    exit(-1);
}
void X86Translator::translate_cmpunordps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpunordps\n";
    exit(-1);
}
void X86Translator::translate_cmpneqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpneqps\n";
    exit(-1);
}
void X86Translator::translate_cmpnltps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnltps\n";
    exit(-1);
}
void X86Translator::translate_cmpnleps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnleps\n";
    exit(-1);
}
void X86Translator::translate_cmpordps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpordps\n";
    exit(-1);
}
void X86Translator::translate_cmppd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmppd\n";
    exit(-1);
}
void X86Translator::translate_cmpeqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpeqpd\n";
    exit(-1);
}
void X86Translator::translate_cmpltpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpltpd\n";
    exit(-1);
}
void X86Translator::translate_cmplepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmplepd\n";
    exit(-1);
}
void X86Translator::translate_cmpunordpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpunordpd\n";
    exit(-1);
}
void X86Translator::translate_cmpneqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpneqpd\n";
    exit(-1);
}
void X86Translator::translate_cmpnltpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnltpd\n";
    exit(-1);
}
void X86Translator::translate_cmpnlepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpnlepd\n";
    exit(-1);
}
void X86Translator::translate_cmpordpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpordpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpss\n";
    exit(-1);
}
void X86Translator::translate_vcmpeqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpltss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpltss\n";
    exit(-1);
}
void X86Translator::translate_vcmpless(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpless\n";
    exit(-1);
}
void X86Translator::translate_vcmpunordss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunordss\n";
    exit(-1);
}
void X86Translator::translate_vcmpneqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpnltss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnltss\n";
    exit(-1);
}
void X86Translator::translate_vcmpnless(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnless\n";
    exit(-1);
}
void X86Translator::translate_vcmpordss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpordss\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_uqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_uqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpngess(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngess\n";
    exit(-1);
}
void X86Translator::translate_vcmpngtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngtss\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalsess(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalsess\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_oqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_oqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpgess(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgess\n";
    exit(-1);
}
void X86Translator::translate_vcmpgtss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgtss\n";
    exit(-1);
}
void X86Translator::translate_vcmptruess(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptruess\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_osss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_osss\n";
    exit(-1);
}
void X86Translator::translate_vcmplt_oqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplt_oqss\n";
    exit(-1);
}
void X86Translator::translate_vcmple_oqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmple_oqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpunord_sss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunord_sss\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_usss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_usss\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlt_uqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlt_uqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpnle_uqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnle_uqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpord_sss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpord_sss\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_usss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_usss\n";
    exit(-1);
}
void X86Translator::translate_vcmpnge_uqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnge_uqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpngt_uqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngt_uqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalse_osss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalse_osss\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_osss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_osss\n";
    exit(-1);
}
void X86Translator::translate_vcmpge_oqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpge_oqss\n";
    exit(-1);
}
void X86Translator::translate_vcmpgt_oqss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgt_oqss\n";
    exit(-1);
}
void X86Translator::translate_vcmptrue_usss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptrue_usss\n";
    exit(-1);
}
void X86Translator::translate_vcmpsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpltsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpltsd\n";
    exit(-1);
}
void X86Translator::translate_vcmplesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpunordsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunordsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnltsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnltsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpordsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpordsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_uqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_uqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngtsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngtsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalsesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalsesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_oqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_oqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgtsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgtsd\n";
    exit(-1);
}
void X86Translator::translate_vcmptruesd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptruesd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_ossd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_ossd\n";
    exit(-1);
}
void X86Translator::translate_vcmplt_oqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplt_oqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmple_oqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmple_oqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpunord_ssd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunord_ssd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_ussd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_ussd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlt_uqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlt_uqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnle_uqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnle_uqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpord_ssd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpord_ssd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_ussd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_ussd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnge_uqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnge_uqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngt_uqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngt_uqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalse_ossd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalse_ossd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_ossd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_ossd\n";
    exit(-1);
}
void X86Translator::translate_vcmpge_oqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpge_oqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgt_oqsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgt_oqsd\n";
    exit(-1);
}
void X86Translator::translate_vcmptrue_ussd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptrue_ussd\n";
    exit(-1);
}
void X86Translator::translate_vcmpps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpps\n";
    exit(-1);
}
void X86Translator::translate_vcmpeqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpltps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpltps\n";
    exit(-1);
}
void X86Translator::translate_vcmpleps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpleps\n";
    exit(-1);
}
void X86Translator::translate_vcmpunordps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunordps\n";
    exit(-1);
}
void X86Translator::translate_vcmpneqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpnltps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnltps\n";
    exit(-1);
}
void X86Translator::translate_vcmpnleps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnleps\n";
    exit(-1);
}
void X86Translator::translate_vcmpordps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpordps\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_uqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_uqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpngeps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngeps\n";
    exit(-1);
}
void X86Translator::translate_vcmpngtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngtps\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalseps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalseps\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_oqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_oqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpgeps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgeps\n";
    exit(-1);
}
void X86Translator::translate_vcmpgtps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgtps\n";
    exit(-1);
}
void X86Translator::translate_vcmptrueps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptrueps\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_osps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_osps\n";
    exit(-1);
}
void X86Translator::translate_vcmplt_oqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplt_oqps\n";
    exit(-1);
}
void X86Translator::translate_vcmple_oqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmple_oqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpunord_sps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunord_sps\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_usps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_usps\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlt_uqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlt_uqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpnle_uqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnle_uqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpord_sps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpord_sps\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_usps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_usps\n";
    exit(-1);
}
void X86Translator::translate_vcmpnge_uqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnge_uqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpngt_uqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngt_uqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalse_osps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalse_osps\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_osps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_osps\n";
    exit(-1);
}
void X86Translator::translate_vcmpge_oqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpge_oqps\n";
    exit(-1);
}
void X86Translator::translate_vcmpgt_oqps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgt_oqps\n";
    exit(-1);
}
void X86Translator::translate_vcmptrue_usps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptrue_usps\n";
    exit(-1);
}
void X86Translator::translate_vcmppd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmppd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpltpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpltpd\n";
    exit(-1);
}
void X86Translator::translate_vcmplepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpunordpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunordpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnltpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnltpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpordpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpordpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_uqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_uqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngtpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngtpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalsepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalsepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_oqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_oqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgtpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgtpd\n";
    exit(-1);
}
void X86Translator::translate_vcmptruepd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptruepd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_ospd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_ospd\n";
    exit(-1);
}
void X86Translator::translate_vcmplt_oqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmplt_oqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmple_oqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmple_oqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpunord_spd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpunord_spd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_uspd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_uspd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnlt_uqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnlt_uqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnle_uqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnle_uqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpord_spd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpord_spd\n";
    exit(-1);
}
void X86Translator::translate_vcmpeq_uspd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpeq_uspd\n";
    exit(-1);
}
void X86Translator::translate_vcmpnge_uqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpnge_uqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpngt_uqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpngt_uqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpfalse_ospd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpfalse_ospd\n";
    exit(-1);
}
void X86Translator::translate_vcmpneq_ospd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpneq_ospd\n";
    exit(-1);
}
void X86Translator::translate_vcmpge_oqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpge_oqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmpgt_oqpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmpgt_oqpd\n";
    exit(-1);
}
void X86Translator::translate_vcmptrue_uspd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction vcmptrue_uspd\n";
    exit(-1);
}
void X86Translator::translate_ud0(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ud0\n";
    exit(-1);
}

void X86Translator::translate_endbr32(GuestInst *Inst) {}
void X86Translator::translate_endbr64(GuestInst *Inst) {}
