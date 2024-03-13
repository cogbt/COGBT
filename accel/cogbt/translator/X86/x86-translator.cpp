#include "x86-translator.h"

#include <sstream>

#include "emulator.h"
#include "host-info.h"
#include "qemu/osdep.h"
#include "llvm/IR/InlineAsm.h"

void X86Translator::DeclareExternalSymbols() {
    /* Mod->getOrInsertGlobal("PFTable", ArrayType::get(Int8Ty, 256)); */
#ifdef CONFIG_COGBT_JMP_CACHE
    JMPCacheAddr = Mod->getOrInsertGlobal("cogbt_jmp_cache", Int64PtrTy);
#endif

    // Declare epilogue.
    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    Function::Create(FuncTy, Function::ExternalLinkage, "epilogue", Mod.get());
    Function::Create(FuncTy, Function::ExternalLinkage, "AOTEpilogue",
                     Mod.get());
    /* Function *EpilogFunc = Function::Create(FuncTy,
     * Function::ExternalLinkage, */
    /*                                       "epilogue", Mod.get()); */
    /* EpilogFunc->addFnAttr(Attribute::NoReturn); */
}

Type *X86Translator::X86RegTyToLLVMTy(X86RegType type) {
    switch (type) {
    default:
        fprintf(stderr, "unsupported x86 reg size(%d).\n",
                GetRegTypeBits(type));
        exit(-1);
    case X86RegGPRType:
        return Int64Ty;
    case X86RegXMMType:
        return V2F64Ty;
    case X86RegFPRType:
        return FP64Ty;
    }
}

void X86Translator::GMRStatesResize(vector<pair<int, int>> arr) {
    int nums = 0;
    for (auto &t : arr)
        nums += t.second;
    GMRStates.resize(nums);
    GMRVals.resize(nums);

    int i = 0;
    for (auto &t : arr) {
        for (int j = 0; j < t.second; ++j) {
            X86RegType type = (X86RegType)t.first;
            assert(type >= 0 && type < GetNumX86RegType());
            GMRStates[i] = Builder.CreateAlloca(X86RegTyToLLVMTy(type), nullptr,
                                                GetGRegName(type, j));
            GMRVals[i].clear();
            ++i;
        }
    }
    assert(i == nums);
}

Value *X86Translator::GetGMRStates(int type, int gid) {
    switch (type) {
    default:
        fprintf(stderr, "unsupported x86 reg type.\n");
        exit(-1);
    case X86RegGPRType:
        assert(gid >= 0 && gid < GetNumGPRs());
        return GMRStates[gid];
    case X86RegXMMType:
        assert(gid >= 0 && gid < GetNumGXMMs());
        return GMRStates[gid + GetNumGPRs()];
    case X86RegFPRType:
        assert(gid >= 0 && gid < GetNumFPRs());
        return GMRStates[gid + GetNumGXMMs() + GetNumGPRs()];
    }
}

void X86Translator::SetGMRStates(int type, int gid, Value *value) {
    switch (type) {
    default:
        fprintf(stderr, "unsupported x86 reg type.\n");
        exit(-1);
    case X86RegGPRType:
        assert(gid >= 0 && gid < GetNumGPRs());
        GMRStates[gid] = value;
        break;
    case X86RegXMMType:
        assert(gid >= 0 && gid < GetNumGXMMs());
        GMRStates[gid + GetNumGPRs()] = value;
        break;
    case X86RegFPRType:
        assert(gid >= 0 && gid < GetNumFPRs());
        GMRStates[gid + GetNumGXMMs() + GetNumGPRs()] = value;
    }
}

GMRValue X86Translator::GetGMRVals(int type, int gid) {
    switch (type) {
    default:
        fprintf(stderr, "unsupported x86 reg type.\n");
        exit(-1);
    case X86RegGPRType:
        assert(gid >= 0 && gid < GetNumGPRs());
        return GMRVals[gid];
    case X86RegXMMType:
        assert(gid >= 0 && gid < GetNumGXMMs());
        return GMRVals[gid + GetNumGPRs()];
    case X86RegFPRType:
        assert(gid >= 0 && gid < GetNumFPRs());
        return GMRVals[gid + GetNumGXMMs() + GetNumGPRs()];
    }
}

void X86Translator::SetGMRVals(int type, int gid, Value *value, bool dirty) {
    switch (type) {
    default:
        fprintf(stderr, "unsupported x86 reg type.\n");
        exit(-1);
    case X86RegGPRType:
        assert(gid >= 0 && gid < GetNumGPRs());
        GMRVals[gid].set(value, dirty);
        break;
    case X86RegXMMType:
        assert(gid >= 0 && gid < GetNumGXMMs());
        GMRVals[gid + GetNumGPRs()].set(value, dirty);
        break;
    case X86RegFPRType:
        assert(gid >= 0 && gid < GetNumFPRs());
        GMRVals[gid + GetNumGXMMs() + GetNumGPRs()].set(value, dirty);
    }
}

void X86Translator::InitializeFunction(StringRef Name) {
    TransFunc = nullptr;
    for (auto &V : GMRStates)
        V = nullptr;
    for (auto &V : GMRVals)
        V.clear();
    ExitBB = EntryBB = CurrBB = nullptr;

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
    // Set TransFunc debug info metadata.
    DISubprogram *SP =
        DIB->createFunction(DIF, Name, "", DIF, 0, STy, 0, DINode::FlagZero,
                            DISubprogram::SPFlagDefinition);
    TransFunc->setSubprogram(SP);

    // Create entry block. This block allocates stack objects to cache host
    // mapped physical registers, binds physical registers to llvm values and
    // stores these values into corresponding stack objects.
    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Allocate stack objects for guest mapped registers.
    GMRStatesResize({{X86RegGPRType, GetNumGPRs()},
                     {X86RegXMMType, GetNumGXMMs()},
                     {X86RegFPRType, GetNumFPRs()}});

    // Binds all mapped host physical registers with llvm value.
    for (int i = 0; i < GetNumGPRs() - GetNumSpecialGPRs(); i++) {
        Value *GMRVal = GetPhysicalRegValue(HostRegNames[GPRToHMR(i)],
                                            X86RegTyToLLVMTy(X86RegGPRType));
        SetGMRVals(X86RegGPRType, i, GMRVal, false);
    }
    SetGMRVals(X86RegGPRType, X86Config::EFLAG,
               GetPhysicalRegValue(HostRegNames[GPRToHMR(X86Config::EFLAG)],
                                   X86RegTyToLLVMTy(X86RegGPRType)),
               true);
    for (int i = 0; i < GetNumGXMMs(); i++) {
        Value *GMRVal = GetPhysicalRegValue(HostLSXRegNames[GXMMToHMR(i)],
                                            X86RegTyToLLVMTy(X86RegXMMType));
        SetGMRVals(X86RegXMMType, i, GMRVal, false);
    }
    for (int i = 0; i < GetNumFPRs(); i++) {
        Value *GMRVal = GetPhysicalRegValue(HostFPRegNames[GFPRToHMR(i)],
                                            X86RegTyToLLVMTy(X86RegFPRType));
        SetGMRVals(X86RegFPRType, i, GMRVal, false);
    }

    // Initialize cpu env register.
    CPUEnv = GetPhysicalRegValue(HostRegNames[ENVReg], Int64Ty);
    CPUEnv = Builder.CreateIntToPtr(CPUEnv, Int8PtrTy);

    // Store physical register value(a.k.a guest state) into stack object.
    for (int i = 0; i < GetNumGPRs(); i++) {
        Builder.CreateStore(GetGMRVals(X86RegGPRType, i).getValue(),
                            GetGMRStates(X86RegGPRType, i));
    }
    for (int i = 0; i < GetNumGXMMs(); i++) {
        Builder.CreateStore(GetGMRVals(X86RegXMMType, i).getValue(),
                            GetGMRStates(X86RegXMMType, i));
    }
    for (int i = 0; i < GetNumFPRs(); i++) {
        Builder.CreateStore(GetGMRVals(X86RegFPRType, i).getValue(),
                            GetGMRStates(X86RegFPRType, i));
    }

    // Create exit Block. It is only used as a label at the end of a function.
    // This block loads values in stack object and sync these
    // values into physical registers.
    ExitBB = BasicBlock::Create(Context, "exit", TransFunc);
    Builder.SetInsertPoint(ExitBB);

    Builder.CreateCall(Mod->getFunction("epilogue"));
    Builder.CreateUnreachable();

#if 0
    for (int i = 0; i < GetNumGMRs(); i++) {
        // Load latest guest state values.
        Value *GMRVal = Builder.CreateLoad(Int64Ty, GMRStates[i]);

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(HostRegNames[GMRToHMR(i)], GMRVal);
    }
    Value *IntEnv = Builder.CreatePtrToInt(CPUEnv, Int64Ty);
    SetPhysicalRegValue(HostRegNames[HostS2], IntEnv);

    // Call Epilogue to do context switch.
    Function *Func = Mod->getFunction("epilogue");
    Builder.CreateCall(Func);
    /* Builder.CreateRetVoid(); */
    Builder.CreateUnreachable();

    // Insert a default branch of EntryBB to ExitBB.
#endif
    Builder.SetInsertPoint(EntryBB);
    Builder.CreateBr(ExitBB);

    // Debug
    /* Mod->print(outs(), nullptr); */
}

void X86Translator::BindPhysicalReg() {
    for (int i = 0; i < GetNumGPRs(); i++) {
        // Load latest guest state values.
        Value *GMRVal = Builder.CreateLoad(X86RegTyToLLVMTy(X86RegGPRType),
                                           GetGMRStates(X86RegGPRType, i));

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(HostRegNames[GPRToHMR(i)], GMRVal,
                            X86RegTyToLLVMTy(X86RegGPRType));
    }
    Value *IntEnv = Builder.CreatePtrToInt(CPUEnv, Int64Ty);
    SetPhysicalRegValue(HostRegNames[ENVReg], IntEnv, Int64Ty);

    for (int i = 0; i < GetNumGXMMs(); i++) {
        Value *GMRVal = Builder.CreateLoad(X86RegTyToLLVMTy(X86RegXMMType),
                                           GetGMRStates(X86RegXMMType, i));
        SetPhysicalRegValue(HostLSXRegNames[GXMMToHMR(i)], GMRVal,
                            X86RegTyToLLVMTy(X86RegXMMType));
    }

    for (unsigned int i = 0; i < (unsigned int)GetNumFPRs(); i++) {
        Value *GMRVal = Builder.CreateLoad(X86RegTyToLLVMTy(X86RegFPRType),
                                           GetGMRStates(X86RegFPRType, i));
        // x87 rotate
        int temp = (i - CurrTBTop) & 7;
        SetPhysicalRegValue(HostFPRegNames[GFPRToHMR(temp)], GMRVal,
                            X86RegTyToLLVMTy(X86RegFPRType));
    }
}

void X86Translator::SetLBTFlag(Value *FV, int mask) {
    FunctionType *FuncTy = FunctionType::get(VoidTy, {Int64Ty, Int32Ty}, false);
    CallFunc(FuncTy, "llvm.loongarch.x86mtflag", {FV, ConstInt(Int32Ty, mask)});
}

Value *X86Translator::GetLBTFlag(int mask) {
    FunctionType *FuncTy = FunctionType::get(Int64Ty, Int32Ty, false);
    return CallFunc(FuncTy, "llvm.loongarch.x86mfflag",
                    ConstInt(Int32Ty, mask));
}

void X86Translator::GenPrologue() {
    if (aotmode == JIT) // JIT
        InitializeModule();

    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage,
                                 "AOTPrologue", Mod.get());
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr(Attribute::NoUnwind);
    TransFunc->addFnAttr(Attribute::Naked);
    /* TransFunc->addFnAttr("cogbt"); */

    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Bind all needed physical reg to value
    Value *HostRegValues[NumHostRegs] = {nullptr};
    HostRegValues[HostSP] = GetPhysicalRegValue(HostRegNames[HostSP], Int64Ty);
    HostRegValues[HostA0] = GetPhysicalRegValue(HostRegNames[HostA0], Int64Ty);
    HostRegValues[HostA1] = GetPhysicalRegValue(HostRegNames[HostA1], Int64Ty);
    for (int i = 0; i < NumHostCSRs; i++) {
        int RegID = HostCSRs[i];
        HostRegValues[RegID] = GetPhysicalRegValue(
            HostRegNames[RegID], X86RegTyToLLVMTy(X86RegGPRType));
    }

    // Note: The callee-saved registers that need to save in LSX and FPR
    // are the same, and FP registers are the lower 64 bits of LSX registers.
    Value *HostLSXValues[NumHostLSXRegs] = {nullptr};
    for (int i = 0; i < NumHostLSXCSRs; i++) {
        int RegID = HostLSXCSRs[i];
        HostLSXValues[RegID] = GetPhysicalRegValue(
            HostLSXRegNames[RegID], X86RegTyToLLVMTy(X86RegXMMType));
    }

    // Adjust $sp
    Value *OldSP = HostRegValues[HostSP];
    Value *NewSP = Builder.CreateAdd(OldSP, ConstantInt::get(Int64Ty, -256));
    HostRegValues[HostSP] = NewSP;

    // Save Callee-Saved-Registers, including $s0-$s8, $fp and $ra
    Type *CSRArrayTy =
        ArrayType::get(X86RegTyToLLVMTy(X86RegGPRType), NumHostCSRs);
    Value *CSRPtrs = Builder.CreateIntToPtr(NewSP, CSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostCSRs; i++) {
        Value *CurrCSRPtr = Builder.CreateGEP(
            CSRArrayTy, CSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        Builder.CreateStore(HostRegValues[HostCSRs[i]], CurrCSRPtr);
    }

    Value *LSXSP = Builder.CreateAdd(NewSP, ConstantInt::get(Int64Ty, 12 * 8));
    /* NumHostCSRs * 8)); */
    Type *LSXCSRArrayTy =
        ArrayType::get(X86RegTyToLLVMTy(X86RegXMMType), NumHostLSXCSRs);
    Value *LSXCSRPtrs =
        Builder.CreateIntToPtr(LSXSP, LSXCSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostLSXCSRs; i++) {
        Value *CurrLSXCSRPtr = Builder.CreateGEP(
            LSXCSRArrayTy, LSXCSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        Builder.CreateStore(HostLSXValues[HostLSXCSRs[i]], CurrLSXCSRPtr);
    }

    // Get transalted code entry and ENV value
    Value *CodeEntry = HostRegValues[HostA1];
    Value *ENV = Builder.CreateIntToPtr(HostRegValues[HostA0], Int8PtrTy);

    // Load guest state into mapped registers from env
    vector<Value *> GuestVals(GetNumGPRs());
    for (int i = 0; i < GetNumGPRs(); i++) {
        int Off = 0;
        if (i < EFLAG)
            Off = GuestStateOffset(i);
        else
            Off = GuestEflagOffset();
        Value *Addr =
            Builder.CreateGEP(Int8Ty, ENV, ConstantInt::get(Int64Ty, Off));
        Value *Ptr = Builder.CreateBitCast(Addr, Int64PtrTy);
        GuestVals[i] = Builder.CreateLoad(X86RegTyToLLVMTy(X86RegGPRType), Ptr);
    }
    vector<Value *> GuestXMMVals(GetNumGXMMs());
    for (int i = 0; i < GetNumGXMMs(); i++) {
        int Off = GuestXMMOffset(i);
        Value *Addr =
            Builder.CreateGEP(Int8Ty, ENV, ConstantInt::get(Int64Ty, Off));
        Value *Ptr = Builder.CreateBitCast(Addr, V2F64PtrTy);
        GuestXMMVals[i] =
            Builder.CreateLoad(X86RegTyToLLVMTy(X86RegXMMType), Ptr);
    }
    vector<Value *> GuestFPRVals(GetNumFPRs());
    for (int i = 0; i < GetNumFPRs(); i++) {
        int Off = GuestFPROffset(i);
        Value *Addr =
            Builder.CreateGEP(Int8Ty, ENV, ConstantInt::get(Int64Ty, Off));
        Value *Ptr = Builder.CreateBitCast(Addr, FP64PtrTy);
        GuestFPRVals[i] =
            Builder.CreateLoad(X86RegTyToLLVMTy(X86RegFPRType), Ptr);
    }

    // Sync GuestVals, EFLAG, ENV, CodeEntry, HostSp to mapped regs
    for (int i = 0; i < EFLAG; i++) {
        SetPhysicalRegValue(HostRegNames[GPRToHMR(i)], GuestVals[i],
                            X86RegTyToLLVMTy(X86RegGPRType));
    }
    SetPhysicalRegValue(HostRegNames[EFLAGReg], GuestVals[EFLAG], Int64Ty);
    SetLBTFlag(GuestVals[EFLAG]);
    SetPhysicalRegValue(HostRegNames[ENVReg], HostRegValues[HostA0], Int64Ty);
    // $r4 maybe modified, sync it.
    SetPhysicalRegValue(HostRegNames[HostA1], CodeEntry, Int64Ty);
    SetPhysicalRegValue(HostRegNames[HostSP], NewSP, Int64Ty);

    for (int i = 0; i < GetNumGXMMs(); i++) {
        SetPhysicalRegValue(HostLSXRegNames[GXMMToHMR(i)], GuestXMMVals[i],
                            X86RegTyToLLVMTy(X86RegXMMType));
    }
    for (int i = 0; i < GetNumFPRs(); i++) {
        SetPhysicalRegValue(HostFPRegNames[GFPRToHMR(i)], GuestFPRVals[i],
                            X86RegTyToLLVMTy(X86RegFPRType));
    }

    // Jump to CodeEntry
    CodeEntry = GetPhysicalRegValue(HostRegNames[HostA1], Int64Ty);
    CodeEntry = Builder.CreateIntToPtr(CodeEntry, FuncTy->getPointerTo());
    Builder.CreateCall(FuncTy, CodeEntry);
    Builder.CreateUnreachable();

    // debug
    /* Mod->print(outs(), nullptr); */
    /* exit(0); //test */
}

void X86Translator::GenEpilogue() {
    if (aotmode == JIT) // JIT
        InitializeModule();

    TransFunc = Mod->getFunction("AOTEpilogue");
    /* FunctionType *FuncTy = FunctionType::get(VoidTy, false); */
    /* TransFunc = Function::Create(FuncTy, Function::ExternalLinkage,
     * "epilogue", */
    /*                              Mod.get()); */
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr(Attribute::NoUnwind);
    TransFunc->addFnAttr(Attribute::Naked);
    /* TransFunc->addFnAttr("cogbt"); */

    EntryBB = BasicBlock::Create(Context, "entry", TransFunc);
    Builder.SetInsertPoint(EntryBB);

    // Store GMR into CPUX86State
    Value *OldSP = GetPhysicalRegValue(HostRegNames[HostSP], Int64Ty);
    vector<Value *> GuestVals(GetNumGPRs());
    for (int i = 0; i < GetNumGPRs(); i++) {
        GuestVals[i] = GetPhysicalRegValue(HostRegNames[GPRToHMR(i)],
                                           X86RegTyToLLVMTy(X86RegGPRType));
        if (i == X86Config::EFLAG) {
            Value *LBTFlag = GetLBTFlag();
            Value *DF = Builder.CreateAnd(GuestVals[i],
                                          ConstInt(Int64Ty, DF_BIT | 0x202));
            /* DF = Builder.CreateOr(DF, ConstInt(Int64Ty, 0x202)); */
            GuestVals[i] = Builder.CreateOr(LBTFlag, DF);
        }
    }
    vector<Value *> GuestXMMVals(GetNumGXMMs());
    for (int i = 0; i < GetNumGXMMs(); i++) {
        GuestXMMVals[i] = GetPhysicalRegValue(HostLSXRegNames[GXMMToHMR(i)],
                                              X86RegTyToLLVMTy(X86RegXMMType));
    }
    vector<Value *> GuestFPRVals(GetNumFPRs());
    for (int i = 0; i < GetNumFPRs(); i++) {
        GuestFPRVals[i] = GetPhysicalRegValue(HostFPRegNames[GFPRToHMR(i)],
                                              X86RegTyToLLVMTy(X86RegFPRType));
    }

    CPUEnv = GetPhysicalRegValue(HostRegNames[ENVReg], Int64Ty);
    CPUEnv = Builder.CreateIntToPtr(CPUEnv, Int8PtrTy);
    for (int i = 0; i < GetNumGPRs(); i++) {
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

    for (int i = 0; i < GetNumGXMMs(); i++) {
        int off = GuestXMMOffset(i);
        Value *Addr =
            Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int64Ty, off));
        Value *Ptr = Builder.CreateBitCast(Addr, V2F64PtrTy);
        Builder.CreateStore(GuestXMMVals[i], Ptr, true);
    }

    for (int i = 0; i < GetNumFPRs(); i++) {
        int off = GuestFPROffset(i);
        Value *Addr =
            Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int64Ty, off));
        Value *Ptr = Builder.CreateBitCast(Addr, FP64PtrTy);
        Builder.CreateStore(GuestFPRVals[i], Ptr, true);
    }

    // Load CSRs.
    Value *HostRegValues[NumHostRegs] = {nullptr};
    Value *NewSP = Builder.CreateAdd(OldSP, ConstInt(Int64Ty, 256));
    Type *CSRArrayTy =
        ArrayType::get(X86RegTyToLLVMTy(X86RegGPRType), NumHostCSRs);
    Value *CSRPtrs = Builder.CreateIntToPtr(OldSP, CSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostCSRs; i++) {
        Value *CurrCSRPtr = Builder.CreateGEP(
            CSRArrayTy, CSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        HostRegValues[HostCSRs[i]] =
            Builder.CreateLoad(X86RegTyToLLVMTy(X86RegGPRType), CurrCSRPtr);
    }

    Value *HostLSXRegValues[NumHostLSXRegs] = {nullptr};
    /* Value *LSXSP = Builder.CreateAdd(OldSP, ConstInt(Int64Ty, NumHostCSRs *
     * 8)); */
    Value *LSXSP = Builder.CreateAdd(OldSP, ConstInt(Int64Ty, 12 * 8));
    Type *LSXCSRArrayTy =
        ArrayType::get(X86RegTyToLLVMTy(X86RegXMMType), NumHostLSXCSRs);
    Value *LSXCSRPtrs =
        Builder.CreateIntToPtr(LSXSP, LSXCSRArrayTy->getPointerTo());
    for (int i = 0; i < NumHostLSXCSRs; i++) {
        Value *CurrLSXCSRPtr = Builder.CreateGEP(
            LSXCSRArrayTy, LSXCSRPtrs,
            {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, i)});
        HostLSXRegValues[HostLSXCSRs[i]] =
            Builder.CreateLoad(X86RegTyToLLVMTy(X86RegXMMType), CurrLSXCSRPtr);
    }

    // Bind all CSR values with physical regs.
    for (int i = 0; i < NumHostCSRs; i++) {
        SetPhysicalRegValue(HostRegNames[HostCSRs[i]],
                            HostRegValues[HostCSRs[i]],
                            X86RegTyToLLVMTy(X86RegGPRType));
    }
    SetPhysicalRegValue(HostRegNames[HostSP], NewSP, Int64Ty);
    SetPhysicalRegValue(HostRegNames[HostA0], ConstInt(Int64Ty, -1), Int64Ty);
    for (int i = 0; i < NumHostLSXCSRs; i++) {
        SetPhysicalRegValue(HostLSXRegNames[HostLSXCSRs[i]],
                            HostLSXRegValues[HostLSXCSRs[i]],
                            X86RegTyToLLVMTy(X86RegXMMType));
    }

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
    if (GMRVals[GMRId].hasValue()) {
        Builder.CreateStore(GMRVals[GMRId].getValue(), GMRStates[GMRId]);
        // GMRValue should be invalidated once branch.
        GMRVals[GMRId].clear();
    }
}

void X86Translator::FlushGMRValue(X86MappedRegsId GMRId) {
    assert((unsigned)GMRId >= 0 && (unsigned)GMRId < GMRVals.size() &&
           "GMRId is too large!");
    int Off = -1;
    if (X86MappedRegsIdToRegTy(GMRId) == X86RegGPRType)
        Off = GMRId < X86Config::EFLAG ? GuestStateOffset(GMRId)
                                       : GuestEflagOffset();
    else if (X86MappedRegsIdToRegTy(GMRId) == X86RegXMMType)
        Off = GuestXMMOffset(GMRId - GetNumGPRs());
    else if (X86MappedRegsIdToRegTy(GMRId) == X86RegFPRType)
        Off = GuestFPROffset(GMRId - GetNumGXMMs() - GetNumGMRs());
    assert(Off >= 0 && "GMRId is not support");

    Value *Addr =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstantInt::get(Int64Ty, Off));
    Type *Ty = X86RegTyToLLVMTy(X86MappedRegsIdToRegTy(GMRId));
    Value *Ptr = Builder.CreateBitCast(Addr, Ty->getPointerTo());
    Value *GMRV = LoadGMRValue(Ty, GMRId);
    if (GMRId == X86Config::EFLAG) {
        Value *Flag = GetLBTFlag();
        GMRV = Builder.CreateAnd(GMRV, ConstInt(Int64Ty, DF_BIT | 0x202));
        /* GMRV = Builder.CreateOr(GMRV, ConstInt(Int64Ty, 0x202)); */
        GMRV = Builder.CreateOr(GMRV, Flag);
    }
    Builder.CreateStore(GMRV, Ptr, true);
}

void X86Translator::ReloadGMRValue(X86MappedRegsId GMRId) {
    assert((unsigned)GMRId >= 0 && (unsigned)GMRId < GMRVals.size() &&
           "GMRId is too large!");
    int Off = 0;
    if (X86MappedRegsIdToRegTy(GMRId) == X86RegGPRType)
        Off = GMRId < X86Config::EFLAG ? GuestStateOffset(GMRId)
                                       : GuestEflagOffset();
    else if (X86MappedRegsIdToRegTy(GMRId) == X86RegXMMType)
        Off = GuestXMMOffset(GMRId - GetNumGPRs());
    else if (X86MappedRegsIdToRegTy(GMRId) == X86RegFPRType)
        Off = GuestFPROffset(GMRId - GetNumGXMMs() - GetNumGMRs());
    assert(Off >= 0 && "GMRId is not support");

    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, Off));
    Type *Ty = X86RegTyToLLVMTy(X86MappedRegsIdToRegTy(GMRId));
    Addr = Builder.CreateBitCast(Addr, Ty->getPointerTo());
    Value *V = Builder.CreateLoad(Ty, Addr);
    StoreGMRValue(V, GMRId); // EFLAG DF also should be reload
    if (GMRId == X86Config::EFLAG) {
        // sync to inner lbt flag register
        SetLBTFlag(V);
    }
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
    case 10:
        return Int80Ty;
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

Value *X86Translator::LoadGMRValue(Type *Ty, X86MappedRegsId GMRId,
                                   bool isHSubReg) {
    /* assert(Ty->isIntegerTy() && "Type is not a integer type!"); */
    assert((unsigned)GMRId >= 0 && (unsigned)GMRId < GMRVals.size() &&
           "GMRId is too large!");

    X86RegType type = X86MappedRegsIdToRegTy(GMRId);
    int gid = X86MappedRegsIdToId(GMRId);

    Value *V = nullptr;
    bool hasValue = true;
    if (GMRVals[GMRId].hasValue()) {
        V = GMRVals[GMRId].getValue();
    } else {
        V = Builder.CreateLoad(X86RegTyToLLVMTy(type), GetGMRStates(type, gid));
        SetGMRVals(type, gid, V, false);
        hasValue = false;
    }
    if (Ty == V4F32Ty && V->getType() == V2F64Ty) {
        V = Builder.CreateBitCast(V, V4F32Ty);
    }

    if (Ty == V->getType()) {
        return V;
    } else if (type == X86RegGPRType) {
        assert(V->getType()->isIntegerTy() && Ty->isIntegerTy());
        if (isHSubReg) {
            assert(Ty->getIntegerBitWidth() == 8 && "HSubReg should be 8 bit");
            if (hasValue) {
                V = Builder.CreateLShr(V, ConstInt(V->getType(), 8));
                V = Builder.CreateAnd(V, ConstInt(V->getType(), 0xff));
            } else {
                V = Builder.CreateAShr(V, ConstInt(Int64Ty, 8));
            }
        }
        V = Builder.CreateTrunc(V, Ty);
        return V;
    } else if (type == X86RegXMMType) {
        assert(Ty->isFloatTy() || Ty->isDoubleTy());
        if (Ty->isFloatTy()) {
            V = Builder.CreateBitCast(V, V4F32Ty);
        }
        V = Builder.CreateExtractElement(V, ConstantInt::get(Int32Ty, 0));
        return V;
    } else if (type == X86RegFPRType) {
        // std::string typeStr;
        // llvm::raw_string_ostream rso(typeStr);
        // V->getType()->print(rso);
        // dbgs() << rso.str() << "\n";
        // Ty->print(rso);
        // dbgs() << rso.str() << "\n";
        // assert(Ty->isDoubleTy() || Ty->isFloatTy());
        if (Ty == FP32Ty) {
            V = Builder.CreateFPTrunc(V, FP32Ty);
        }
        // else if (Ty == FP64Ty) {
        //     // do nothing
        // } else if (Ty == FP80Ty) {
        //     V = Builder.CreateFPExt(V, FP80Ty);
        // }
        else {
            std::string typeStr;
            llvm::raw_string_ostream rso(typeStr);
            V->getType()->print(rso);
            Ty->print(rso);
            dbgs() << rso.str() << "\n";
            assert(0 && "it is developing...");
        }
        return V;
    } else {
        fprintf(stderr, "unsupported type.\n");
        exit(-1);
    }
}

void X86Translator::StoreGMRValue(Value *V, X86MappedRegsId GMRId,
                                  bool isHSubReg) {
    /* assert(V->getType()->isIntegerTy() && "V is not a interger type!"); */
    assert((unsigned)GMRId >= 0 && (unsigned)GMRId < GMRVals.size() &&
           "GMRId is too large!");

    X86RegType type = X86MappedRegsIdToRegTy(GMRId);
    int gid = X86MappedRegsIdToId(GMRId);

    if (V->getType() == V4F32Ty) {
        V = Builder.CreateBitCast(V, V2F64Ty);
    }

    if (type == X86RegFPRType && V->getType() == Int64Ty) {
        V = Builder.CreateBitCast(V, FP64Ty);
    } else if (type == X86RegFPRType && V->getType() == Int32Ty) {
        V = Builder.CreateBitCast(V, FP32Ty);
        V = Builder.CreateFPExt(V, FP64Ty);
    }
    // else if (type == X86RegFPRType && V->getType() == Int80Ty) {
    //     V = Builder.CreateBitCast(V, FP80Ty);
    //     V = Builder.CreateFPTrunc(V, FP64Ty);
    // }

    if (V->getType() == X86RegTyToLLVMTy(type)) {
        SetGMRVals(type, gid, V, true);
    } else if (type == X86RegGPRType) {
        if (GMRVals[GMRId].hasValue()) {
            assert(V->getType()->isIntegerTy() && "V is not a interger type!");
            uint64_t mask = ~((1ULL << V->getType()->getIntegerBitWidth()) - 1);
            if (isHSubReg) {
                mask = 0xffffffffffff00ff;
                assert(V->getType()->getIntegerBitWidth() == 8);
                V = Builder.CreateZExt(V, Int64Ty);
                V = Builder.CreateShl(V, ConstInt(Int64Ty, 8));
            } else
                V = Builder.CreateZExt(V, Int64Ty);
            Value *OldV = Builder.CreateAnd(GMRVals[GMRId].getValue(),
                                            ConstantInt::get(Int64Ty, mask));
            Value *Res = Builder.CreateOr(OldV, V);
            SetGMRVals(type, GMRId, Res, true);
            /* GMRVals[GMRId].set(Res, true); */
        } else {
            // GMRVals haven't cached GMRId, so store V into GMRStates directly.
            Value *Addr = Builder.CreateBitCast(GMRStates[GMRId],
                                                V->getType()->getPointerTo());
            if (isHSubReg) {
                assert(V->getType()->getIntegerBitWidth() == 8);
                Addr = Builder.CreateGEP(Int8Ty, Addr, ConstInt(Int64Ty, 1));
            }
            Builder.CreateStore(V, Addr);
        }
    } else if (type == X86RegXMMType) {
        assert(V->getType()->isFloatTy() || V->getType()->isDoubleTy());
        if (V->getType() == V4F32Ty) {
            V = Builder.CreateBitCast(V, V2F64Ty);
        }

        if (V->getType()->isFloatTy()) {
            if (GMRVals[GMRId].hasValue()) {
                Value *OldVal =
                    Builder.CreateBitCast(GMRVals[GMRId].getValue(), V4F32Ty);
                Value *Res = Builder.CreateInsertElement(
                    OldVal, V, ConstantInt::get(Int32Ty, 0));
                Res = Builder.CreateBitCast(Res, V2F64Ty);
                SetGMRVals(type, gid, Res, true);
            } else {
                Value *Addr = Builder.CreateBitCast(
                    GMRStates[GMRId], V->getType()->getPointerTo());
                Builder.CreateStore(V, Addr);
            }
        } else if (V->getType()->isDoubleTy()) {
            if (GMRVals[GMRId].hasValue()) {
                Value *Res = Builder.CreateInsertElement(
                    GMRVals[GMRId].getValue(), V, ConstantInt::get(Int32Ty, 0));
                SetGMRVals(type, gid, Res, true);
            } else {
                Value *Addr = Builder.CreateBitCast(
                    GMRStates[GMRId], V->getType()->getPointerTo());
                Builder.CreateStore(V, Addr);
            }
        }
    } else if (type == X86RegFPRType) {
        assert(0 && "it is developing...");
        // if (V->getType() == FP32Ty) {
        //     V = Builder.CreateFPExt(V, FP64Ty);
        // } else if (V->getType() == FP80Ty) {
        //     V = Builder.CreateFPTrunc(V, FP64Ty);
        // } else {
        //     assert(0 && "it is developing...");
        // }
        // TODO: SetGMRVals
    } else {
        fprintf(stderr, "unsupported type.\n");
        exit(-1);
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
            /* int baseReg = OpndHdl.GetBaseReg(); */
            X86MappedRegsId baseReg =
                IdToX86MappedRegsId(X86RegGPRType, OpndHdl.GetBaseReg());
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
        case 1:
            shift = 0;
            break;
        case 2:
            shift = 1;
            break;
        case 4:
            shift = 2;
            break;
        case 8:
            shift = 3;
            break;
        default:
            llvm_unreachable("scale should be power of 2");
        }
        Index =
            LoadGMRValue(Int64Ty, IdToX86MappedRegsId(X86RegGPRType, indexReg));
        Index = Builder.CreateShl(Index, ConstantInt::get(Int64Ty, shift));
        if (!MemAddr)
            MemAddr = Index;
        else
            MemAddr = Builder.CreateAdd(MemAddr, Index);
    }
    // Disp field is valud, add this offset.
    /* if (Opnd->mem.disp) { */
    if (!MemAddr) {
        MemAddr = Builder.CreateAdd(ConstInt(Int64Ty, 0),
                                    ConstInt(Int64Ty, Opnd->mem.disp));
    } else {
        MemAddr = Builder.CreateAdd(MemAddr, ConstInt(Int64Ty, Opnd->mem.disp));
    }
    /* } */

    /* MemAddr = Builder.CreateIntToPtr(MemAddr, LLVMTy->getPointerTo()); */
    return MemAddr;
}

Value *X86Translator::LoadOperand(X86Operand *Opnd, Type *LoadTy) {
    Type *LLVMTy = !LoadTy ? GetOpndLLVMType(Opnd) : LoadTy;
    X86OperandHandler OpndHdl(Opnd);

    Value *Res = nullptr;

    if (OpndHdl.isImm()) {
        Res = ConstInt(LLVMTy, Opnd->imm);
        /* Res = Builder.CreateAdd(ConstantInt::get(LLVMTy, 0), */
        /*                         ConstantInt::get(LLVMTy, Opnd->imm)); */
    } else if (OpndHdl.isReg()) {
        if (OpndHdl.isGPR()) {
            Res = LoadGMRValue(LLVMTy, (X86MappedRegsId)OpndHdl.GetGMR(),
                               OpndHdl.isHSubReg());
        } else if (OpndHdl.isXMM()) {
            // The current implementation is to read xmm reg from CPUX86State
            // directly.
#if 0
            int off = GuestXMMOffset(OpndHdl.GetXMMID());
            Value *Addr =
                Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
            Addr = Builder.CreateBitCast(Addr, LLVMTy->getPointerTo());
            Res = Builder.CreateLoad(LLVMTy, Addr);
#else
            Res =
                LoadGMRValue(LLVMTy, (X86MappedRegsId)OpndHdl.GetGMR(), false);
#endif
        } else if (OpndHdl.isFPR()) {
            if (LLVMTy == Int32Ty)
                LLVMTy = FP32Ty;
            else if (LLVMTy == Int64Ty)
                LLVMTy = FP64Ty;
            else
                llvm_unreachable("Unhandled FPR operand type!");

            Res = LoadGMRValue(
                LLVMTy,
                IdToX86MappedRegsId(X86RegFPRType,
                                    (OpndHdl.GetFPRID() + CurrTBTop) & 7),
                false);
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
    assert(OpndHdl.isMMX() || OpndHdl.isXMM() || OpndHdl.isFPR() ||
           (ResVal->getType()->isIntegerTy() &&
            ResVal->getType()->getIntegerBitWidth() >=
                (unsigned)OpndHdl.getOpndSize() * 8) ||
           (ResVal->getType()->isFloatTy() && OpndHdl.getOpndSize() == 4) ||
           (ResVal->getType()->isDoubleTy() &&
            (OpndHdl.getOpndSize() == 4 || OpndHdl.getOpndSize() == 8)) ||
           (ResVal->getType() == V4F32Ty || ResVal->getType() == V2F64Ty));

    // If Dest isn't MMX/XMM, Trunc ResVal to the same bitwidth as DestOpnd.
    if (!OpndHdl.isMMX() && !OpndHdl.isXMM()) {
        if (ResVal->getType()->isIntegerTy() &&
            ResVal->getType()->getIntegerBitWidth() >
                (unsigned)(OpndHdl.getOpndSize() << 3)) {
            ResVal = Builder.CreateTrunc(ResVal, GetOpndLLVMType(DestOpnd));
        } else if (ResVal->getType()->isDoubleTy() &&
                   OpndHdl.getOpndSize() == 4) {
            ResVal = Builder.CreateFPTrunc(ResVal, FP32Ty);
        }
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
        StoreGMRValue(ResVal, (X86MappedRegsId)OpndHdl.GetGMR(),
                      OpndHdl.isHSubReg());
    } else if (OpndHdl.isMem()) {
        Value *MemAddr = CalcMemAddr(DestOpnd);
        /* if (!ResVal->getType()->isIntegerTy(64)) { */
        /*     MemAddr = Builder.CreateIntToPtr(MemAddr, ResVal->getType()); */
        /* } */
        MemAddr =
            Builder.CreateIntToPtr(MemAddr, ResVal->getType()->getPointerTo());
        Builder.CreateStore(ResVal, MemAddr);
    } else if (OpndHdl.isXMM()) {
#if 0
        // Current implementation is to store value into CPUX86State directly.
        int off = GuestXMMOffset(OpndHdl.GetXMMID());
        Value *Addr =
            Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
        Addr = Builder.CreateBitCast(Addr, ResVal->getType()->getPointerTo());
        Builder.CreateStore(ResVal, Addr);
#else
        StoreGMRValue(ResVal, (X86MappedRegsId)OpndHdl.GetGMR(), false);
#endif
    } else if (OpndHdl.isFPR()) {
        StoreGMRValue(ResVal,
                      IdToX86MappedRegsId(X86RegFPRType,
                                          (OpndHdl.GetFPRID() + CurrTBTop) & 7),
                      false);
    } else {
        llvm_unreachable("Unhandled StoreOperand type!");
    }
}

void X86Translator::FlushXMMT0(Value *XMMV, Type *FlushTy) {
    if (!FlushTy)
        FlushTy = Int128PtrTy;
    int off = GuestXMMT0Offset();
    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
    Addr = Builder.CreateBitCast(Addr, FlushTy);
    Builder.CreateStore(XMMV, Addr);
}

void X86Translator::FlushMMXT0(Value *MMXV, Type *FlushTy) {
    if (!FlushTy)
        FlushTy = Int64PtrTy;
    int off = GuestMMXT0Offset();
    Value *Addr = Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, off));
    Addr = Builder.CreateBitCast(Addr, FlushTy);
    Builder.CreateStore(MMXV, Addr);
}

CallInst *X86Translator::CallFunc(FunctionType *FuncTy, StringRef Name,
                                  ArrayRef<Value *> Args) {
    if (Name.startswith("helper_f")) {
        dbgs() << "Call Float Func: " << Name << "\n";
    }
#if (LLVM_VERSION_MAJOR > 8)
    FunctionCallee F = Mod->getOrInsertFunction(Name, FuncTy);
    CallInst *callInst = Builder.CreateCall(FuncTy, F.getCallee(), Args);
#else
    Value *Func = Mod->getOrInsertFunction(Name, FuncTy);
    CallInst *callInst = Builder.CreateCall(Func, Args);
#endif
    return callInst;
}

void X86Translator::AddExternalSyms() {
    for (int i = 0; i < SymTableSize; i++)
        EE->addGlobalMapping(SymTable[i].key, (uint64_t)SymTable[i].val);
}

void X86Translator::GetLBTIntrinsic(StringRef Name, Value *Src0, Value *Src1) {
    if (Src1) {
        FunctionType *FTy = FunctionType::get(
            VoidTy, {Src1->getType(), Src0->getType()}, false);
        CallFunc(FTy, Name, {Src1, Src0});
    } else {
        FunctionType *FTy = FunctionType::get(VoidTy, {Src0->getType()}, false);
        CallFunc(FTy, Name, {Src0});
    }
}

CallInst *X86Translator::GetCogbtExitIntrinsic(ArrayRef<Value *> Args) {
    FunctionType *FTy = FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
    return CallFunc(FTy, "llvm.loongarch.cogbtexit", Args);
}

std::string GetSuffixAccordingType(Type *Ty) {
    switch (Ty->getIntegerBitWidth()) {
    case 8:
        return ".b";
    case 16:
        return ".h";
    case 32:
        return ".w";
    case 64:
        return ".d";
    default:
        llvm_unreachable("Error LBT Type!");
    }
}

void X86Translator::CalcEflag(GuestInst *Inst, Value *Dest, Value *Src0,
                              Value *Src1) {
    Type *Src0Ty = nullptr, *Src1Ty = nullptr;
    if (Src0)
        Src0Ty = Src0->getType();
    if (Src1)
        Src1Ty = Src1->getType();
    if (Src0 && Src0->getType()->getIntegerBitWidth() != 64)
        Src0 = Builder.CreateSExt(Src0, Int64Ty);
    if (Src1 && Src1->getType()->getIntegerBitWidth() != 64)
        Src1 = Builder.CreateSExt(Src1, Int64Ty);

    X86InstHandler InstHdl(Inst);
    std::string Name;
    switch (Inst->guestInst->id) {
    case X86_INS_ADD:
    case X86_INS_XADD:
        Name = std::string("llvm.loongarch.x86add") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_ADC:
        Name = std::string("llvm.loongarch.x86adc") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_INC:
        Name = std::string("llvm.loongarch.x86inc") +
               GetSuffixAccordingType(Src0Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_DEC:
        Name = std::string("llvm.loongarch.x86dec") +
               GetSuffixAccordingType(Src0Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_CMPSB:
    case X86_INS_CMPSW:
    case X86_INS_CMPSD:
    case X86_INS_CMPSQ:
    case X86_INS_SCASB:
    case X86_INS_SCASW:
    case X86_INS_SCASD:
    case X86_INS_SCASQ:
    case X86_INS_CMPXCHG:
    case X86_INS_CMPXCHG8B:
    case X86_INS_NEG:
    case X86_INS_CMP:
    case X86_INS_SUB:
        Name = std::string("llvm.loongarch.x86sub") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_SBB:
        Name = std::string("llvm.loongarch.x86sbc") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_XOR:
        Name = std::string("llvm.loongarch.x86xor") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_TEST:
    case X86_INS_AND:
        Name = std::string("llvm.loongarch.x86and") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_OR:
        Name = std::string("llvm.loongarch.x86or") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_SAL:
    case X86_INS_SHL: {
        X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
        if (OpndHdl.isImm()) {
            Name = std::string("llvm.loongarch.x86slli") +
                   GetSuffixAccordingType(Src1Ty);
            GetLBTIntrinsic(Name, ConstInt(Int32Ty, OpndHdl.getIMM()), Src1);
        } else {
            Name = std::string("llvm.loongarch.x86sll") +
                   GetSuffixAccordingType(Src1Ty);
            GetLBTIntrinsic(Name, Src0, Src1);
        }
        break;
    }
    case X86_INS_SHR: {
        X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
        if (OpndHdl.isImm()) {
            Name = std::string("llvm.loongarch.x86srli") +
                   GetSuffixAccordingType(Src1Ty);
            GetLBTIntrinsic(Name, ConstInt(Int32Ty, OpndHdl.getIMM()), Src1);
        } else {
            Name = std::string("llvm.loongarch.x86srl") +
                   GetSuffixAccordingType(Src1Ty);
            GetLBTIntrinsic(Name, Src0, Src1);
        }
        break;
    }
    case X86_INS_SAR: {
        X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
        if (OpndHdl.isImm()) {
            Name = std::string("llvm.loongarch.x86srai") +
                   GetSuffixAccordingType(Src1->getType());
            GetLBTIntrinsic(Name, ConstInt(Int32Ty, OpndHdl.getIMM()), Src1);
        } else {
            Name = std::string("llvm.loongarch.x86sra") +
                   GetSuffixAccordingType(Src1Ty);
            GetLBTIntrinsic(Name, Src0, Src1);
        }
        break;
    }
    case X86_INS_RCL:
        Name = std::string("llvm.loongarch.x86rcl") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_RCR:
        Name = std::string("llvm.loongarch.x86rcr") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_MUL:
        Name = std::string("llvm.loongarch.x86mul") +
               GetSuffixAccordingType(Src1Ty) + "u";
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_IMUL:
        Name = std::string("llvm.loongarch.x86mul") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_ROR:
        Name = std::string("llvm.loongarch.x86rotr") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_ROL:
        Name = std::string("llvm.loongarch.x86rotl") +
               GetSuffixAccordingType(Src1Ty);
        GetLBTIntrinsic(Name, Src0, Src1);
        break;
    case X86_INS_SHLD:
    case X86_INS_SHRD:
        // Use x86add to calculate SF,ZF,PF and other flags will be
        // calculated in translation function itself.
        Name = std::string("llvm.loongarch.x86add") +
               GetSuffixAccordingType(Dest->getType());
        GetLBTIntrinsic(Name, Dest, ConstInt(Dest->getType(), 0));
        break;
    case X86_INS_AAM:
    case X86_INS_AAD:
    case X86_INS_AAA:
    case X86_INS_DAA:
    case X86_INS_DAS:
    default:
        dbgs() << Inst->guestInst->mnemonic << "\n";
        llvm_unreachable("Unhandled Inst");
    }
    // debug
    /* Value *V = GetLBTFlag(0x3f); */
    /* StoreGMRValue(V, X86Config::EFLAG); */
}

void X86Translator::TranslateInitialize() {
    // Gen prologue and epilogue IR.
    GenPrologue();
    GenEpilogue();
}

void X86Translator::TranslateFinalize() { LLVMTranslator::TranslateFinalize(); }

// Translate a TU in each function call.
void X86Translator::Translate() {
    std::stringstream ss;
    ss << std::hex << TU->GetTUEntry();
    std::string Entry(ss.str());

    // Initialize function
    if (aotmode == JIT) { // JIT
        InitializeFunction(Entry);
    }
    if (aotmode == TB_AOT) { // TB AOT mode
        std::stringstream ss;
        ss << std::hex << Entry << "." << std::dec << TU->GetTUPCSize();
        InitializeFunction(ss.str());
    }
    if (aotmode == TU_AOT) { // TU AOT mode
        std::stringstream ss;
        ss << std::hex << Entry << "." << std::dec << TU->GetTUPCSize();
        InitializeFunction(ss.str());
        for (auto &block : *TU) {
            ss.str("");
            ss << std::hex << block.GetBlockEntry();
            std::string Name(ss.str());
            BasicBlock::Create(Context, Name, TransFunc, ExitBB);
        }
    }

    // FIXME: It is only used for tb mode and jit mode.
    assert(TU->size() == 1);
    for (auto &block : *TU) {
        InitializeBlock(block);
        CurrTBTop = block.topin;

        for (auto &inst : block) {
            CurrInst = &inst;
            switch (inst.guestInst->id) {
            default:
                assert(0 && "Unknown x86 opcode!");
#define HANDLE_X86_INST(opcode, name)                                          \
    case opcode:                                                               \
        if (#name[0] == 'f') {                                                 \
            dbgs() << "Translate Float Inst: " << #name << "\n";               \
        }                                                                      \
        translate_##name(&inst);                                               \
        break;
#include "x86-inst.def"
            }
        }

        block.topout = CurrTBTop;
#if 0
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
#endif
        X86InstHandler GuestInstHdl(&*block.rbegin());
        if (!GuestInstHdl.isTerminator()) {
            std::stringstream ss;
            ss << std::hex << GuestInstHdl.getNextPC();
            std::string NextPCStr(ss.str());
            BasicBlock *NextBB = GetBasicBlock(TransFunc, NextPCStr);
            /* assert(NextBB && "nextpc label does not exist."); */

            SyncAllGMRValue();
            if (NextBB)
                Builder.CreateBr(NextBB);
            else { // this label does not in this function, go to epilogue
                Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
                Value *NextPC = ConstInt(Int64Ty, GuestInstHdl.getNextPC());

                BindPhysicalReg();
                Instruction *LinkSlot = GetCogbtExitIntrinsic({NextPC, Off});
                AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
                /* Builder.CreateBr(ExitBB); */
                Builder.CreateCall(Mod->getFunction("epilogue"));
                Builder.CreateUnreachable();
            }
            if (IsExitPC(GuestInstHdl.getPC())) {
                ExitBB->eraseFromParent();
            }
        }
        /* TransFunc->dump(); */
    }
}
