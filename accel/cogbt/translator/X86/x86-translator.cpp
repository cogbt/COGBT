#include "x86-translator.h"
#include "emulator.h"
#include "host-info.h"
#include "llvm/IR/InlineAsm.h"

void X86Translator::DeclareExternalSymbols() {
    Mod->getOrInsertGlobal("PFTable", ArrayType::get(Int8Ty, 256));

    // Declare epilogue.
    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    Function::Create(FuncTy, Function::ExternalLinkage, "epilogue", Mod.get());
    /* Function *EpilogFunc = Function::Create(FuncTy, Function::ExternalLinkage, */
    /*                                       "epilogue", Mod.get()); */
    /* EpilogFunc->addFnAttr(Attribute::NoReturn); */
}

void X86Translator::InitializeFunction(StringRef Name) {
    // Create translation function with (void (*)()) type, C calling convention,
    // and cogbt attribute.
    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc =
        Function::Create(FuncTy, Function::ExternalLinkage, Name, Mod.get());
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr(Attribute::NoUnwind);
    /* TransFunc->addFnAttr(Attribute::Naked); */
    TransFunc->addFnAttr("cogbt");

    // Create entry block. This block allocates stack objects to cache host
    // mapped physical registers, binds physical registers to llvm values and
    // stores these values into corresponding stack objects.
    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Allocate stack objects for guest mapped registers.
    GMRStates.resize(GetNumGMRs());
    GMRVals.resize(GetNumGMRs());
    for (int i = 0; i < GetNumGMRs(); i++) {
        GMRStates[i] = Builder.CreateAlloca(Int64Ty, nullptr, GetGMRName(i));
        GMRVals[i].clear();
    }

    // Binds all mapped host physical registers with llvm value.
    for (int i = 0; i < GetNumGMRs() - GetNumSpecialGMRs(); i++) {
        Value *GMRVal = GetPhysicalRegValue(HostRegNames[GMRToHMR(i)]);
        GMRVals[i].set(GMRVal, false);
    }
    GMRVals[X86Config::EFLAG].set(
        GetPhysicalRegValue(HostRegNames[GMRToHMR(EFLAG)]), true);

    // Initialize cpu env register.
    CPUEnv = GetPhysicalRegValue(HostRegNames[ENVReg]);
    CPUEnv = Builder.CreateIntToPtr(CPUEnv, Int8PtrTy);

    // Store physical register value(a.k.a guest state) into stack object.
    for (int i = 0; i < GetNumGMRs(); i++) {
        Builder.CreateStore(GMRVals[i].getValue(), GMRStates[i]);
    }

    // Create exit Block. This block loads values in stack object and sync these
    // values into physical registers.
    ExitBB = BasicBlock::Create(Context, "exit", TransFunc);
    Builder.SetInsertPoint(ExitBB);
    for (int i = 0; i < GetNumGMRs(); i++) {
        // Load latest guest state values.
        Value *GMRVal = Builder.CreateLoad(Int64Ty, GMRStates[i]);

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(HostRegNames[GMRToHMR(i)], GMRVal);
    }

    // Call Epilogue to do context switch.
    Builder.CreateCall(Mod->getFunction("epilogue"));
    /* Builder.CreateRetVoid(); */
    Builder.CreateUnreachable();

    // Insert a default branch of EntryBB to ExitBB.
    Builder.SetInsertPoint(EntryBB);
    Builder.CreateBr(ExitBB);

    // Debug
    /* Mod->print(outs(), nullptr); */
}

void X86Translator::GenPrologue() {
    InitializeModule();

    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage, "prologue",
                                 Mod.get());
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr(Attribute::NoUnwind);
    TransFunc->addFnAttr(Attribute::Naked);
    /* TransFunc->addFnAttr("cogbt"); */

    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Bind all needed physical reg to value
    Value *HostRegValues[NumHostRegs] = {nullptr};
    HostRegValues[HostSP] = GetPhysicalRegValue(HostRegNames[HostSP]);
    HostRegValues[HostA0] = GetPhysicalRegValue(HostRegNames[HostA0]);
    HostRegValues[HostA1] = GetPhysicalRegValue(HostRegNames[HostA1]);
    for (int i = 0; i < NumHostCSRs; i++) {
        int RegID = HostCSRs[i];
        HostRegValues[RegID] = GetPhysicalRegValue(HostRegNames[RegID]);
    }

    // Adjust $sp
    Value *OldSP = HostRegValues[HostSP];
    Value *NewSP = Builder.CreateAdd(OldSP, ConstantInt::get(Int64Ty, -256));
    HostRegValues[HostSP] = NewSP;

    // Save Callee-Saved-Registers, including $s0-$s8, $fp and $ra
    Type *CSRArrayTy = ArrayType::get(Int64Ty, NumHostCSRs);
    Value *CSRPtrs = Builder.CreateIntToPtr(NewSP, CSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostCSRs; i++) {
        Value *CurrCSRPtr = Builder.CreateGEP(
            CSRArrayTy, CSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        Builder.CreateStore(HostRegValues[HostCSRs[i]], CurrCSRPtr);
    }

    // Get transalted code entry and ENV value
    Value *CodeEntry = HostRegValues[HostA1];
    Value *ENV = Builder.CreateIntToPtr(HostRegValues[HostA0], Int8PtrTy);

    // Load guest state into mapped registers
    vector<Value *> GuestVals(GetNumGMRs());
    for (int i = 0; i < GetNumGMRs(); i++) {
        int Off = 0;
        if (i < EFLAG)
            Off = GuestStateOffset(i);
        else
            Off = GuestEflagOffset();
        Value *Addr =
            Builder.CreateGEP(Int8Ty, ENV, ConstantInt::get(Int64Ty, Off));
        Value *Ptr = Builder.CreateBitCast(Addr, Int64PtrTy);
        GuestVals[i] = Builder.CreateLoad(Int64Ty, Ptr);
    }

    // Sync GuestVals, EFLAG, ENV, CodeEntry, HostSp to mapped regs
    for (int i = 0; i < EFLAG; i++) {
        SetPhysicalRegValue(HostRegNames[GMRToHMR(i)], GuestVals[i]);
    }
    SetPhysicalRegValue(HostRegNames[EFLAGReg], GuestVals[EFLAG]);
    SetPhysicalRegValue(HostRegNames[ENVReg], HostRegValues[HostA0]);
    // $r4 maybe modified, sync it.
    SetPhysicalRegValue(HostRegNames[HostA1], CodeEntry);
    SetPhysicalRegValue(HostRegNames[HostSP], NewSP);

    // Jump to CodeEntry
    CodeEntry = GetPhysicalRegValue(HostRegNames[HostA1]);
    CodeEntry = Builder.CreateIntToPtr(CodeEntry, FuncTy->getPointerTo());
    Builder.CreateCall(FuncTy, CodeEntry);
    Builder.CreateUnreachable();

    // debug
    /* Mod->print(outs(), nullptr); */
}

void X86Translator::GenEpilogue() {
    InitializeModule();

    TransFunc = Mod->getFunction("epilogue");
    /* FunctionType *FuncTy = FunctionType::get(VoidTy, false); */
    /* TransFunc = Function::Create(FuncTy, Function::ExternalLinkage, "epilogue", */
    /*                              Mod.get()); */
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr(Attribute::NoUnwind);
    TransFunc->addFnAttr(Attribute::Naked);
    /* TransFunc->addFnAttr("cogbt"); */

    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Store GMR into CPUX86State
    Value *OldSP = GetPhysicalRegValue(HostRegNames[HostSP]);
    vector<Value *> GuestVals(GetNumGMRs());
    for (int i = 0; i < GetNumGMRs(); i++) {
        GuestVals[i] = GetPhysicalRegValue(HostRegNames[GMRToHMR(i)]);
    }

    CPUEnv = GetPhysicalRegValue(HostRegNames[ENVReg]);
    CPUEnv = Builder.CreateIntToPtr(CPUEnv, Int8PtrTy);
    for (int i = 0; i < GetNumGMRs(); i++) {
        int Off = 0;
        if (i < X86Config::EFLAG)
            Off = GuestStateOffset(i);
        else
            Off = GuestEflagOffset();
        Value *Addr =
            Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int64Ty, Off));
        Value *Ptr = Builder.CreateBitCast(Addr, Int64PtrTy);
        Builder.CreateStore(GuestVals[i], Ptr, true);
    }

    // Load CSRs.
    Value *HostRegValues[NumHostRegs] = {nullptr};
    Value *NewSP = Builder.CreateAdd(OldSP, ConstInt(Int64Ty, 256));
    Type *CSRArrayTy = ArrayType::get(Int64Ty, NumHostCSRs);
    Value *CSRPtrs = Builder.CreateIntToPtr(OldSP, CSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostCSRs; i++) {
        Value *CurrCSRPtr = Builder.CreateGEP(
            CSRArrayTy, CSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        HostRegValues[HostCSRs[i]] = Builder.CreateLoad(Int64Ty, CurrCSRPtr);
    }

    // Bind all CSR values with physical regs.
    for (int i = 0; i < NumHostCSRs; i++) {
        SetPhysicalRegValue(HostRegNames[HostCSRs[i]],
                            HostRegValues[HostCSRs[i]]);
    }
    SetPhysicalRegValue(HostRegNames[HostSP], NewSP);
    SetPhysicalRegValue(HostRegNames[HostA0], ConstInt(Int64Ty, 0));

    // Return dbt.
    Builder.CreateRetVoid();

    // debug
    /* Mod->print(outs(), nullptr); */
}

void X86Translator::SyncAllGMRValue() {
    for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
        SyncGMRValue(GMRId);
    }
}

void X86Translator::SyncGMRValue(int GMRId) {
    if (GMRVals[GMRId].isDirty()) {
        Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
        GMRVals[GMRId].setDirty(false);
    }
}

void X86Translator::FlushGMRValue(int GMRId) {
    assert(GMRId < (int)GMRVals.size());
    int Off = 0;
    if (GMRId < X86Config::EFLAG)
        Off = GuestStateOffset(GMRId);
    else
        Off = GuestEflagOffset();
    Value *Addr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int64Ty, Off));
    Value *Ptr = Builder.CreateBitCast(Addr, Int64PtrTy);
    Value *GMRV = LoadGMRValue(Int64Ty, GMRId);
    Builder.CreateStore(GMRV, Ptr, true);
}

void X86Translator::ReloadGMRValue(int GMRId) {
    assert(GMRId < (int)GMRVals.size());
    int Off = 0;
    if (GMRId < X86Config::EFLAG)
        Off = GuestStateOffset(GMRId);
    else
        Off = GuestEflagOffset();
    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, Off));
    Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
    StoreGMRValue(Builder.CreateLoad(Int64Ty, Addr), GMRId);
}

Type *X86Translator::GetOpndLLVMType(X86Operand *Opnd) {
    switch (Opnd->size) {
    case 1:
        return Int8Ty;
    case 2:
        return Int16Ty;
    case 4:
        return Int32Ty;
    case 8:
        return Int64Ty;
    case 16:
        return Int128Ty;
    case 32:
        return Int256Ty;
    default:
        llvm_unreachable("Unexpected operand size(not 1,2,4,8 bytes)");
    }
}

Type *X86Translator::GetOpndLLVMType(int size) {
    switch (size) {
    case 1:
        return Int8Ty;
    case 2:
        return Int16Ty;
    case 4:
        return Int32Ty;
    case 8:
        return Int64Ty;
    default:
        llvm_unreachable("Unexpected operand size(not 1,2,4,8 bytes)");
    }
}

Value *X86Translator::LoadGMRValue(Type *Ty, int GMRId) {
    assert(Ty->isIntegerTy() && "Type is not a integer type!");
    if (GMRVals[GMRId].hasValue()) {
        Value *V = GMRVals[GMRId].getValue();
        if (Ty->isIntegerTy(64)) {
            return V;
        } else {
            V = Builder.CreateTrunc(V, Ty);
            return V;
        }
    }
    assert(GMRVals.size() > (unsigned)GMRId);

    /* auto CurrBB = Builder.GetInsertBlock(); */
    /* if (!CurrBB->empty()) { */
    /*     Builder.SetInsertPoint(&CurrBB->front()); */
    /* } */

    Value *V = Builder.CreateLoad(Int64Ty, GMRStates[GMRId]);
    GMRVals[GMRId].set(V, false);

    /* Builder.SetInsertPoint(CurrBB); */

    if (!Ty->isIntegerTy(64))
        V = Builder.CreateTrunc(V, Ty);
    return V;
}

void X86Translator::StoreGMRValue(Value *V, int GMRId) {
    assert(V->getType()->isIntegerTy() && "V is not a interger type!");
    assert((unsigned)GMRId < GMRVals.size() && "GMRId is too large!");

    if (V->getType()->isIntegerTy(64)) {
        GMRVals[GMRId].set(V, true);
    } else {
        if (GMRVals[GMRId].hasValue()) {
            uint64_t mask = ~((1ULL << V->getType()->getIntegerBitWidth()) - 1);
            Value *OldV = Builder.CreateAnd(GMRVals[GMRId].getValue(),
                                            ConstantInt::get(Int64Ty, mask));
            Value *Res = Builder.CreateOr(OldV, Builder.CreateZExt(V, Int64Ty));
            GMRVals[GMRId].set(Res, true);
        } else {
            // GMRVals haven't cached GMRId, so store V into GMRStates directly.
            Value *Addr = Builder.CreateBitCast(GMRStates[GMRId],
                                                V->getType()->getPointerTo());
            Builder.CreateStore(V, Addr);
        }
    }
}

Value *X86Translator::CalcMemAddr(X86Operand *Opnd) {
    X86OperandHandler OpndHdl(Opnd);
    assert(OpndHdl.isMem() && "CalcMemAddr should handle memory operand!");

    /* Type *LLVMTy = GetOpndLLVMType(Opnd); */
    Value *MemAddr = nullptr, *Seg = nullptr, *Base = nullptr, *Index = nullptr;

    // Memory operand has segment register, load its segment base addr.
    if (Opnd->mem.segment != X86_REG_INVALID) {
        Value *Addr = Builder.CreateGEP(
            Int8Ty, CPUEnv,
            ConstantInt::get(Int64Ty, GuestSegOffset(Opnd->mem.segment)));
        Addr = Builder.CreateBitCast(Addr, Int64PtrTy);
        Seg = Builder.CreateLoad(Int64Ty, Addr);
        MemAddr = Seg;
    }
    // Base field is valid, calculate base.
    if (Opnd->mem.base != X86_REG_INVALID) {
        if (Opnd->mem.base == X86_REG_RIP) {
            X86InstHandler InstHdl(CurrInst);
            Base = ConstInt(Int64Ty, InstHdl.getNextPC());
        } else {
            int baseReg = OpndHdl.GetBaseReg();
            Base = LoadGMRValue(Int64Ty, baseReg);
        }
        if (!MemAddr)
            MemAddr = Base;
        else {
            MemAddr = Builder.CreateAdd(MemAddr, Base);
        }
    }
    // Index field is valid, caculate index*scale.
    if (Opnd->mem.index != X86_REG_INVALID) {
        int indexReg = OpndHdl.GetIndexReg();
        int scale = Opnd->mem.scale;
        int shift = 0;
        switch (scale) {
            case 1: shift = 0; break;
            case 2: shift = 1; break;
            case 4: shift = 2; break;
            case 8: shift = 3; break;
            default: llvm_unreachable("scale should be power of 2");
        }
        Index = LoadGMRValue(Int64Ty, indexReg);
        Index = Builder.CreateShl(Index, ConstantInt::get(Int64Ty, shift));
        if (!MemAddr)
            MemAddr = Index;
        else
            MemAddr = Builder.CreateAdd(MemAddr, Index);
    }
    // Disp field is valud, add this offset.
    if (Opnd->mem.disp) {
        MemAddr = Builder.CreateAdd(MemAddr,
                                    ConstantInt::get(Int64Ty, Opnd->mem.disp));
    }

    /* MemAddr = Builder.CreateIntToPtr(MemAddr, LLVMTy->getPointerTo()); */
    return MemAddr;
}

Value *X86Translator::LoadOperand(X86Operand *Opnd, Type *LoadTy) {
    Type *LLVMTy = !LoadTy ? GetOpndLLVMType(Opnd) : LoadTy;
    X86OperandHandler OpndHdl(Opnd);

    Value *Res = nullptr;

    if (OpndHdl.isImm()) {
        Res = Builder.CreateAdd(ConstantInt::get(LLVMTy, 0),
                                ConstantInt::get(LLVMTy, Opnd->imm));
    } else if (OpndHdl.isReg()) {
        if (OpndHdl.isGPR()) {
            Res = LoadGMRValue(LLVMTy, OpndHdl.GetGMRID());
        } else if (OpndHdl.isXMM()) {
            // The current implementation is to read xmm reg from CPUX86State
            // directly.
            int off = GuestXMMOffset(OpndHdl.GetXMMID());
            Value *Addr =
                Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
            Addr = Builder.CreateBitCast(Addr, LLVMTy->getPointerTo());
            Res = Builder.CreateLoad(LLVMTy, Addr);
        } else {
            llvm_unreachable("Unhandled register operand type!");
        }
    } else {
        assert(OpndHdl.isMem() && "Opnd type is illegal!");
        Res = CalcMemAddr(Opnd);
        Res = Builder.CreateIntToPtr(Res, LLVMTy->getPointerTo());
        Res = Builder.CreateLoad(LLVMTy, Res);
    }
    return Res;
}

// If DestOpnd is MMX or XMM register, then the dest operand type depends on
// ResVal, Otherwise the type of DestOpnd is the real type.
void X86Translator::StoreOperand(Value *ResVal, X86Operand *DestOpnd) {
    X86OperandHandler OpndHdl(DestOpnd);

    // If DestOpnd isn't MMX or XMM, then the bitwidth of ResVal is greater or
    // equal than DestOpnd.
    assert(OpndHdl.isMMX() || OpndHdl.isXMM() || 
           ResVal->getType()->getIntegerBitWidth() >=
               (unsigned)OpndHdl.getOpndSize() * 8);

    // If Dest isn't MMX/XMM, Trunc ResVal to the same bitwidth as DestOpnd.
    if (!OpndHdl.isMMX() && !OpndHdl.isXMM() &&
        ResVal->getType()->getIntegerBitWidth() >
            (unsigned)(OpndHdl.getOpndSize() << 3)) {
        ResVal = Builder.CreateTrunc(ResVal, GetOpndLLVMType(DestOpnd));
    }

    if (OpndHdl.isGPR()) {
        // if dest reg is 32-bit, zext it first
        if (OpndHdl.getOpndSize() == 4) {
            // If src is 32-bit, zext it directly.
            // If src is 64-bit, trunc and then zext.
            if (ResVal->getType()->isIntegerTy(32)) {
                ResVal = Builder.CreateZExt(ResVal, Int64Ty);
            } else if (ResVal->getType()->isIntegerTy(64)) {
                ResVal = Builder.CreateTrunc(ResVal, Int32Ty);
                ResVal = Builder.CreateZExt(ResVal, Int64Ty);
            }
        }
        StoreGMRValue(ResVal, OpndHdl.GetGMRID());
    } else if (OpndHdl.isMem()) {
        Value *MemAddr = CalcMemAddr(DestOpnd);
        /* if (!ResVal->getType()->isIntegerTy(64)) { */
        /*     MemAddr = Builder.CreateIntToPtr(MemAddr, ResVal->getType()); */
        /* } */
        MemAddr =
            Builder.CreateIntToPtr(MemAddr, ResVal->getType()->getPointerTo());
        Builder.CreateStore(ResVal, MemAddr);
    } else if (OpndHdl.isXMM()) {
        // Current implementation is to store value into CPUX86State directly.
        int off = GuestXMMOffset(OpndHdl.GetXMMID());
        Value *Addr =
            Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
        Addr = Builder.CreateBitCast(Addr, ResVal->getType()->getPointerTo());
        Builder.CreateStore(ResVal, Addr);
    } else {
        llvm_unreachable("Unhandled StoreOperand type!");
    }
}

void X86Translator::FlushXMMT0(Value *XMMV, Type *FlushTy) {
    if (!FlushTy) FlushTy = Int128PtrTy;
    int off = GuestXMMT0Offset();
    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
    Addr = Builder.CreateBitCast(Addr, FlushTy);
    Builder.CreateStore(XMMV, Addr);
}

void X86Translator::FlushMMXT0(Value *MMXV, Type *FlushTy) {
    if (!FlushTy) FlushTy = Int64PtrTy;
    int off = GuestMMXT0Offset();
    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
    Addr = Builder.CreateBitCast(Addr, FlushTy);
    Builder.CreateStore(MMXV, Addr);
}

Value *X86Translator::CallFunc(FunctionType *FuncTy, std::string Name,
        ArrayRef<Value *> Args) {
#if (LLVM_VERSION_MAJOR > 8)
    FunctionCallee F = Mod->getOrInsertFunction(Name, FuncTy);
    Value *CallInst = Builder.CreateCall(FuncTy, F.getCallee(), Args);
#else
    Value *Func = Mod->getOrInsertFunction(Name, FuncTy);
    Value *CallInst = Builder.CreateCall(Func, Args);
#endif
    return CallInst;
}

void X86Translator::AddExternalSyms() {
    EE->addGlobalMapping("PFTable", X86InstHandler::getPFTable());
    EE->addGlobalMapping("helper_raise_syscall", (uint64_t)helper_raise_syscall);
    EE->addGlobalMapping("helper_divb_AL", (uint64_t)helper_divb_AL_wrapper);
    EE->addGlobalMapping("helper_divw_AX", (uint64_t)helper_divw_AX_wrapper);
    EE->addGlobalMapping("helper_divl_EAX", (uint64_t)helper_divl_EAX_wrapper);
    EE->addGlobalMapping("helper_divq_EAX", (uint64_t)helper_divq_EAX_wrapper);
    EE->addGlobalMapping("helper_rdtsc", (uint64_t)helper_rdtsc_wrapper);
    EE->addGlobalMapping("helper_pxor_xmm", (uint64_t)helper_pxor_xmm_wrapper);
    EE->addGlobalMapping("helper_pxor_mmx", (uint64_t)helper_pxor_mmx_wrapper);
    EE->addGlobalMapping("helper_pcmpeqb_xmm", (uint64_t)helper_pcmpeqb_xmm_wrapper);
    EE->addGlobalMapping("helper_pcmpeqb_mmx", (uint64_t)helper_pcmpeqb_mmx_wrapper);
    EE->addGlobalMapping("helper_pmovmskb_xmm", (uint64_t)helper_pmovmskb_xmm_wrapper);
    EE->addGlobalMapping("helper_pmovmskb_mmx", (uint64_t)helper_pmovmskb_mmx_wrapper);
    EE->addGlobalMapping("helper_punpcklbw_xmm", (uint64_t)helper_punpcklbw_xmm_wrapper);
    EE->addGlobalMapping("helper_punpcklbw_mmx", (uint64_t)helper_punpcklbw_mmx_wrapper);
    EE->addGlobalMapping("helper_punpcklwd_xmm", (uint64_t)helper_punpcklwd_xmm_wrapper);
    EE->addGlobalMapping("helper_punpcklwd_mmx", (uint64_t)helper_punpcklwd_mmx_wrapper);
}

// CF is set if the addition of two numbers causes a carry out of the most
// significant bits added or substraction of two numbers requires a borrow
// into the most significant bits substracted.
void X86Translator::GenCF(GuestInst *Inst, Value *Dest, Value *Src0,
                          Value *Src1) {
    X86InstHandler InstHdl(Inst);
    switch (Inst->id) {
    default:
        printf("0x%lx  %s\t%s\n", Inst->address, Inst->mnemonic, Inst->op_str);
        llvm_unreachable("GenCF Unhandled Inst ID\n");
    case X86_INS_AND: // CF is cleared
    case X86_INS_OR:
    case X86_INS_TEST:
    case X86_INS_XOR: {
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        StoreGMRValue(ClearEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_SCASB:
    case X86_INS_SCASW:
    case X86_INS_SCASD:
    case X86_INS_SUB:
    case X86_INS_CMPSB:
    case X86_INS_CMPSW:
    case X86_INS_CMPSD:
    case X86_INS_CMP:
    case X86_INS_CMPXCHG:
    case X86_INS_DEC: {
        Value *IsLess = Builder.CreateICmpULT(Src1, Src0);
        Value *CFBit = Builder.CreateSelect(IsLess, ConstInt(Int64Ty, CF_BIT),
                                            ConstInt(Int64Ty, 0));
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_SHL:
    case X86_INS_SAL: {
        // CF contains the value of the last bit shifted left out of the
        // destination operand.
        Value *Shift = Builder.CreateAdd(Src0, ConstInt(Src1->getType(), -1));
        Value *LB = Builder.CreateShl(Src1, Shift);
        LB = Builder.CreateLShr(LB,
            ConstInt(LB->getType(), Src1->getType()->getIntegerBitWidth() - 1));
        LB = Builder.CreateAnd(LB, ConstInt(LB->getType(), 1));
        Value *CFBit = Builder.CreateZExt(LB, Int64Ty);

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_SHR:
    case X86_INS_SAR: {
        /// CF contains the value of the last bit shifted out of the destination
        /// opnd.
        Value *Shift = Builder.CreateAdd(Src0, ConstInt(Src1->getType(), -1));
        Value *LB = Builder.CreateLShr(Src1, Shift);
        LB = Builder.CreateAnd(LB, ConstInt(LB->getType(), 1));
        Value *CFBit = Builder.CreateZExt(LB, Int64Ty);

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_ADD:
    case X86_INS_XADD: {
        /// dest < src
        Value *isLess = Builder.CreateICmpULT(Dest, Src0);
        Value *CFBit = Builder.CreateZExt(isLess, Int64Ty);

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_MUL: {
        // If upper half == 1 then CF = 1
        Value *UpperHalf = nullptr;
        if (!Src0) {
            assert(Dest->getType()->getIntegerBitWidth() == 16 && "mul error");
            UpperHalf = Builder.CreateLShr(Dest, ConstInt(Dest->getType(), 8));
        } else {
            UpperHalf = Src0;
        }
        Value *isSet =
            Builder.CreateICmpNE(UpperHalf, ConstInt(UpperHalf->getType(), 0));

        Value *CFBit = Builder.CreateSelect(isSet, ConstInt(Int64Ty, CF_BIT),
                                            ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_IMUL: {
        // if Dest != SEXT Src then CF is set to 1.
        Value *SExtSrc = Builder.CreateSExt(Src0, Dest->getType());
        Value *isDiff = Builder.CreateICmpNE(Dest, SExtSrc);
        Value *CFBit = Builder.CreateSelect(isDiff, ConstInt(Int64Ty, CF_BIT),
                                            ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_NEG: {
        // if Dest is zero, then CF is set to zero.
        Value *isZero = Builder.CreateICmpEQ(Dest, ConstInt(Dest->getType(), 0));
        Value *CFBit = Builder.CreateSelect(isZero, ConstInt(Int64Ty, CF_BIT),
                                            ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getCFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, CFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }

    }
}

// If the sum of two numbers with the sign bits off yields a result number with
// the sign bit on, the "overflow" flag is turned on.
// 0100 + 0100 = 1000 (overflow flag is turned on)
//
// If the sum of two numbers with the sign bits on yields a result number with
// the sign bit off, the "overflow" flag is turned on.
// 1000 + 1000 = 0000 (overflow flag is turned on)
void X86Translator::GenOF(GuestInst *Inst, Value *Dest, Value *Src0,
                          Value *Src1) {
    X86InstHandler InstHdl(Inst);
    switch (Inst->id) {
    default:
        llvm_unreachable("GenOF Unhandled Inst ID\n");
    case X86_INS_AND: // OF is cleared
    case X86_INS_OR:
    case X86_INS_TEST:
    case X86_INS_XOR: {
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getOFMask());
        StoreGMRValue(ClearEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_SUB:
    case X86_INS_CMP:
    case X86_INS_CMPXCHG:
    case X86_INS_DEC: {
        /// Src1 OP Src0 -> Dest overflow
        /// iff. Src1 has a different sign bit than Src0 and Dest.
        Value *SrcDiff = Builder.CreateXor(Src1, Src0);
        Value *DestDiff = Builder.CreateXor(Src1, Dest);
        Value *Overflow = Builder.CreateAnd(SrcDiff, DestDiff);
        Value *IsOverflow =
            Builder.CreateICmpSLT(Overflow, ConstInt(Dest->getType(), 0));
        Value *OFBit = Builder.CreateSelect(
            IsOverflow, ConstInt(Int64Ty, OF_BIT), ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getOFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, OFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_MUL: {
        // If upper half == 1 then OF = 1
        Value *UpperHalf = nullptr;
        if (!Src0) {
            assert(Dest->getType()->getIntegerBitWidth() == 16 && "mul error");
            UpperHalf = Builder.CreateLShr(Dest, ConstInt(Dest->getType(), 8));
        } else {
            UpperHalf = Src0;
        }
        Value *isSet =
            Builder.CreateICmpNE(UpperHalf, ConstInt(UpperHalf->getType(), 0));

        Value *OFBit = Builder.CreateSelect(isSet, ConstInt(Int64Ty, OF_BIT),
                                            ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getOFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, OFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_IMUL: {
        // if Dest != SEXT Src then OF is set to 1.
        Value *SExtSrc = Builder.CreateSExt(Src0, Dest->getType());
        Value *isDiff = Builder.CreateICmpNE(Dest, SExtSrc);
        Value *OFBit = Builder.CreateSelect(isDiff, ConstInt(Int64Ty, OF_BIT),
                                            ConstInt(Int64Ty, 0));

        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getOFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, OFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
        break;
    }
    case X86_INS_NEG: { // TODO
        // OF is set if Dest has a different sign bit with Src0
        /* Value *Val = Builder.CreateAnd(Dest, Src0); */
        /* Val = Builder.CreateLShr( */
        /*     Val, */
        /*     ConstInt(Val->getType(), Val->getType()->getIntegerBitWidth() - 1)); */
        /* Val = Builder.CreateZExt(Val, Int64Ty); */
        /* Val = Builder.CreateShl(Val, ConstInt(Int64Ty, OF_BIT)); */

        /* Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG); */
        /* Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getOFMask()); */
        /* Value *NewEflag = Builder.CreateOr(ClearEflag, Val); */
        /* StoreGMRValue(NewEflag, X86Config::EFLAG); */
        break;
    }
    case X86_INS_SHR: // TODO
    case X86_INS_SAR: // TODO
    case X86_INS_ADD: // TODO
    case X86_INS_INC: // TODO
    case X86_INS_SHL: // TODO
        break;

    }
}

void X86Translator::CalcEflag(GuestInst *Inst, Value *Dest, Value *Src0,
                              Value *Src1) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.CFisDefined()) {
        GenCF(Inst, Dest, Src0, Src1);
    }
    if (InstHdl.OFisDefined()) {
        GenOF(Inst, Dest, Src0, Src1);
    }
    if (InstHdl.ZFisDefined()) {
        Value *IsZero =
            Builder.CreateICmpEQ(Dest, ConstInt(Dest->getType(), 0));
        Value *ZFBit = Builder.CreateSelect(IsZero, ConstInt(Int64Ty, ZF_BIT),
                                            ConstInt(Int64Ty, 0));
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getZFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, ZFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
    }
    if (InstHdl.AFisDefined()) {
        /* Value *AFBit = Builder.CreateXor(Dest, Builder.CreateXor(Src0, Src1)); */
        /* AFBit = Builder.CreateAnd(AFBit, ConstInt(Int64Ty, AF_BIT)); */
        /* Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG); */
        /* Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getAFMask()); */
        /* Value *NewEflag = Builder.CreateOr(ClearEflag, AFBit); */
        /* StoreGMRValue(NewEflag, X86Config::EFLAG); */
    }
    if (InstHdl.PFisDefined()) {
        /* Type *ArrTy = ArrayType::get(Int8Ty, 256); */
        /* Value *PFT = Mod->getGlobalVariable("PFTable"); */
        /* Value *Off = Builder.CreateAnd(Dest, ConstInt(Dest->getType(), 0xff)); */
        /* Value *PFBytePtr = */
        /*     Builder.CreateGEP(ArrTy, PFT, {ConstInt(Int64Ty, 0), Off}); */
        /* Value *PFByte = Builder.CreateLoad(Int8Ty, PFBytePtr); */
        /* Value *PFBit = Builder.CreateZExt(PFByte, Int64Ty); */
        /* Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG); */
        /* Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getPFMask()); */
        /* Value *NewEflag = Builder.CreateOr(ClearEflag, PFBit); */
        /* StoreGMRValue(NewEflag, X86Config::EFLAG); */
    }
    if (InstHdl.SFisDefined()) {
        int shift = Dest->getType()->getIntegerBitWidth() - 1;
        Value *IsSign =
            Builder.CreateAShr(Dest, ConstInt(Dest->getType(), shift));
        IsSign = Builder.CreateICmpNE(IsSign, ConstInt(Dest->getType(), 0));
        Value *SFBit = Builder.CreateSelect(IsSign, ConstInt(Int64Ty, SF_BIT),
                                            ConstInt(Int64Ty, 0));
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getSFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, SFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
    }
}

void X86Translator::Translate() {
    InitializeFunction(std::to_string(TU->GetTUEntry()));
    for (auto &block : *TU) {
        assert(TU->size() && "TU size is expected to be non-zero!");
        InitializeBlock(block);
        for (auto &inst : block) {
            CurrInst = inst;
            switch (inst->id) {
            default:
                assert(0 && "Unknown x86 opcode!");
#define HANDLE_X86_INST(opcode, name)                                          \
    case opcode:                                                               \
        translate_##name(inst);                                                \
        break;
#include "x86-inst.def"
            }
        }
        // In debug mode, ONLY one guest instruction is in a block. So some IRs
        // should be added to save guest pc and jump to epilogue.
        X86InstHandler GuestInstHdl(*block.rbegin());
        if (!GuestInstHdl.isTerminator()) {
            Value *Target = ConstInt(Int64Ty, GuestInstHdl.getNextPC());
            Value *EnvEIP = Builder.CreateGEP(
                Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
            Value *EIPAddr = Builder.CreateBitCast(
                EnvEIP, Target->getType()->getPointerTo());
            Builder.CreateStore(Target, EIPAddr);

            // sync GMRVals into stack.
            for (int GMRId = 0; GMRId < (int)GMRVals.size(); GMRId++) {
                if (GMRVals[GMRId].isDirty()) {
                    Builder.CreateStore(GMRVals[GMRId].getValue(),
                                        GMRStates[GMRId]);
                    GMRVals[GMRId].setDirty(false);
                }
            }
            Builder.CreateBr(ExitBB);
        }
    }
}
