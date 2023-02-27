#include "x86-translator.h"
#include "emulator.h"
#include "host-info.h"
#include "llvm/IR/InlineAsm.h"
#include <sstream>

void X86Translator::DeclareExternalSymbols() {
    /* Mod->getOrInsertGlobal("PFTable", ArrayType::get(Int8Ty, 256)); */

    // Declare epilogue.
    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    Function::Create(FuncTy, Function::ExternalLinkage, "epilogue", Mod.get());
    Function::Create(FuncTy, Function::ExternalLinkage, "AOTEpilogue", Mod.get());
    /* Function *EpilogFunc = Function::Create(FuncTy, Function::ExternalLinkage, */
    /*                                       "epilogue", Mod.get()); */
    /* EpilogFunc->addFnAttr(Attribute::NoReturn); */
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
    Value *IntEnv = Builder.CreatePtrToInt(CPUEnv, Int64Ty);
    SetPhysicalRegValue(HostRegNames[HostS2], IntEnv);

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

void X86Translator::BindPhysicalReg() {
    for (int i = 0; i < GetNumGMRs(); i++) {
        // Load latest guest state values.
        Value *GMRVal = Builder.CreateLoad(Int64Ty, GMRStates[i]);

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(HostRegNames[GMRToHMR(i)], GMRVal);
    }
    Value *IntEnv = Builder.CreatePtrToInt(CPUEnv, Int64Ty);
    SetPhysicalRegValue(HostRegNames[HostS2], IntEnv);
}

void X86Translator::SetLBTFlag(Value *FV, int mask) {
    FunctionType *FuncTy = FunctionType::get(VoidTy, {Int64Ty, Int32Ty}, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86mtflag", FuncTy);
    Builder.CreateCall(FuncTy, Func, {FV, ConstInt(Int32Ty, mask)});
}

Value *X86Translator::GetLBTFlag(int mask) {
    FunctionType *FuncTy = FunctionType::get(Int64Ty, Int32Ty, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86mfflag", FuncTy);
    Value *V = Builder.CreateCall(FuncTy, Func, ConstInt(Int32Ty, mask));
    return V;
}

void X86Translator::GenPrologue() {
    if (aotmode != 1)  // JIT and Function AOT mode
        InitializeModule();

    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage, "AOTPrologue",
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
    SetLBTFlag(GuestVals[EFLAG]);
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
    /* exit(0); //test */
}

void X86Translator::GenEpilogue() {
    if (aotmode != 1)  // JIT and Function AOT mode
        InitializeModule();

    TransFunc = Mod->getFunction("AOTEpilogue");
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
        if (i == X86Config::EFLAG) {
            Value *LBTFlag = GetLBTFlag();
            Value *DF =
                Builder.CreateAnd(GuestVals[i], ConstInt(Int64Ty, DF_BIT|0x202));
            GuestVals[i] = Builder.CreateOr(LBTFlag, DF);
        }
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
    SetPhysicalRegValue(HostRegNames[HostA0], ConstInt(Int64Ty, -1));

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
        /* GMRVals[GMRId].setDirty(false); */
        // GMRValue should be invalidated once branch.
        GMRVals[GMRId].clear();
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
    if (GMRId == X86Config::EFLAG) {
        Value *Flag = GetLBTFlag();
        GMRV = Builder.CreateAnd(GMRV, ConstInt(Int64Ty, DF_BIT|0x202));
        GMRV = Builder.CreateOr(GMRV, Flag);
    }
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
    Value *V = Builder.CreateLoad(Int64Ty, Addr);
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

Value *X86Translator::LoadGMRValue(Type *Ty, int GMRId, bool isHSubReg) {
    assert(Ty->isIntegerTy() && "Type is not a integer type!");
    if (GMRVals[GMRId].hasValue()) {
        Value *V = GMRVals[GMRId].getValue();
        if (Ty->isIntegerTy(64)) {
            return V;
        } else {
            if (isHSubReg) {
                assert(Ty->getIntegerBitWidth() == 8 && "HSubReg should be 8 bit");
                V = Builder.CreateLShr(V, ConstInt(V->getType(), 8));
                V = Builder.CreateAnd(V, ConstInt(V->getType(), 0xff));
            }
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

    if (!Ty->isIntegerTy(64)) {
        if (isHSubReg)
            V = Builder.CreateAShr(V, ConstInt(Int64Ty, 8));
        V = Builder.CreateTrunc(V, Ty);
    }
    return V;
}

void X86Translator::StoreGMRValue(Value *V, int GMRId, bool isHSubReg) {
    assert(V->getType()->isIntegerTy() && "V is not a interger type!");
    assert((unsigned)GMRId < GMRVals.size() && "GMRId is too large!");

    if (V->getType()->isIntegerTy(64)) {
        GMRVals[GMRId].set(V, true);
    } else {
        if (GMRVals[GMRId].hasValue()) {
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
            GMRVals[GMRId].set(Res, true);
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
    /* if (Opnd->mem.disp) { */
    if (!MemAddr) {
        MemAddr = Builder.CreateAdd(ConstInt(Int64Ty, 0),
                                    ConstInt(Int64Ty, Opnd->mem.disp));
    } else {
        MemAddr = Builder.CreateAdd(MemAddr,
                                    ConstInt(Int64Ty, Opnd->mem.disp));
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
            Res = LoadGMRValue(LLVMTy, OpndHdl.GetGMRID(), OpndHdl.isHSubReg());
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
        StoreGMRValue(ResVal, OpndHdl.GetGMRID(), OpndHdl.isHSubReg());
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
    /* EE->addGlobalMapping("PFTable", X86InstHandler::getPFTable()); */
    EE->addGlobalMapping("helper_raise_syscall", (uint64_t)helper_raise_syscall);
    EE->addGlobalMapping("helper_divb_AL", (uint64_t)helper_divb_AL_wrapper);
    EE->addGlobalMapping("helper_divw_AX", (uint64_t)helper_divw_AX_wrapper);
    EE->addGlobalMapping("helper_divl_EAX", (uint64_t)helper_divl_EAX_wrapper);
    EE->addGlobalMapping("helper_divq_EAX", (uint64_t)helper_divq_EAX_wrapper);
    EE->addGlobalMapping("helper_idivb_AL", (uint64_t)helper_idivb_AL_wrapper);
    EE->addGlobalMapping("helper_idivw_AX", (uint64_t)helper_idivw_AX_wrapper);
    EE->addGlobalMapping("helper_idivl_EAX", (uint64_t)helper_idivl_EAX_wrapper);
    EE->addGlobalMapping("helper_idivq_EAX", (uint64_t)helper_idivq_EAX_wrapper);

    EE->addGlobalMapping("helper_rdtsc", (uint64_t)helper_rdtsc_wrapper);
    /* EE->addGlobalMapping("helper_pxor_xmm", (uint64_t)helper_pxor_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_pxor_mmx", (uint64_t)helper_pxor_mmx_wrapper); */
    /* EE->addGlobalMapping("helper_pcmpeqb_xmm", (uint64_t)helper_pcmpeqb_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_pcmpeqb_mmx", (uint64_t)helper_pcmpeqb_mmx_wrapper); */
    EE->addGlobalMapping("helper_pmovmskb_xmm", (uint64_t)helper_pmovmskb_xmm_wrapper);
    EE->addGlobalMapping("helper_pmovmskb_mmx", (uint64_t)helper_pmovmskb_mmx_wrapper);
    /* EE->addGlobalMapping("helper_punpcklbw_xmm", (uint64_t)helper_punpcklbw_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_punpcklbw_mmx", (uint64_t)helper_punpcklbw_mmx_wrapper); */
    /* EE->addGlobalMapping("helper_punpcklwd_xmm", (uint64_t)helper_punpcklwd_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_punpcklwd_mmx", (uint64_t)helper_punpcklwd_mmx_wrapper); */
    EE->addGlobalMapping("helper_pshufd", (uint64_t)helper_pshufd_xmm_wrapper);
    EE->addGlobalMapping("helper_comiss", (uint64_t)helper_comiss_wrapper);
    /* EE->addGlobalMapping("helper_paddb_xmm", (uint64_t)helper_paddb_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_paddl_xmm", (uint64_t)helper_paddl_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_paddw_xmm", (uint64_t)helper_paddw_xmm_wrapper); */
    /* EE->addGlobalMapping("helper_paddq_xmm", (uint64_t)helper_paddq_xmm_wrapper); */
    EE->addGlobalMapping("helper_cvtsi2sd" , (uint64_t)helper_cvtsi2sd_wrapper );
    EE->addGlobalMapping("helper_cvtsq2sd" , (uint64_t)helper_cvtsq2sd_wrapper );
    EE->addGlobalMapping("helper_cvttsd2si", (uint64_t)helper_cvttsd2si_wrapper);
    EE->addGlobalMapping("helper_cvttsd2sq", (uint64_t)helper_cvttsd2sq_wrapper);
    EE->addGlobalMapping("helper_cvttss2si", (uint64_t)helper_cvttss2si_wrapper);
    EE->addGlobalMapping("helper_cvttss2sq", (uint64_t)helper_cvttss2sq_wrapper);
    EE->addGlobalMapping("helper_cvtss2sd" , (uint64_t)helper_cvtss2sd_wrapper );
    EE->addGlobalMapping("helper_cvtsd2ss" , (uint64_t)helper_cvtsd2ss_wrapper );
    EE->addGlobalMapping("helper_cvtsi2ss" , (uint64_t)helper_cvtsi2ss_wrapper );
    EE->addGlobalMapping("helper_cvtsq2ss" , (uint64_t)helper_cvtsq2ss_wrapper );

    EE->addGlobalMapping("helper_fcomi_ST0_FT0_cogbt", (uint64_t)helper_fcomi_ST0_FT0_wrapper);
    EE->addGlobalMapping("helper_fucomi_ST0_FT0_cogbt", (uint64_t)helper_fucomi_ST0_FT0_wrapper);

    EE->addGlobalMapping("helper_cogbt_lookup_tb_ptr", (uint64_t)helper_cogbt_lookup_tb_ptr_wrapper);
}

void X86Translator::GetLBTIntrinsic(StringRef Name, Value *Src0, Value *Src1) {
    if (Src1) {
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Src1->getType(), Src0->getType()}, false);
        Value *Func = Mod->getOrInsertFunction(Name, FTy);
        Builder.CreateCall(FTy, Func, {Src1, Src0});
    } else {
        FunctionType *FTy =
            FunctionType::get(VoidTy, {Src0->getType()}, false);
        Value *Func = Mod->getOrInsertFunction(Name, FTy);
        Builder.CreateCall(FTy, Func, {Src0});

    }
}

std::string GetSuffixAccordingType(Type *Ty) {
    switch (Ty->getIntegerBitWidth()) {
    case 8: return ".b";
    case 16: return ".h";
    case 32: return ".w";
    case 64: return ".d";
    default: llvm_unreachable("Error LBT Type!");
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
    switch (Inst->id) {
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
        // Use x86add to calculate SF,ZF,PF and other flags will be calculated
        // in translation function itself.
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
        dbgs() << Inst->mnemonic << "\n";
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

void X86Translator::TranslateFinalize() {
    LLVMTranslator::TranslateFinalize();
}

void X86Translator::Translate() {
    // FIXME: tb aot initialization.
    if (aotmode == 1) {
        // Do translate initialization.
        TranslateInitialize();
    }

    std::stringstream ss;
    ss << std::hex << TU->GetTUEntry();
    std::string Entry(ss.str());
    /* InitializeFunction(std::to_string(TU->GetTUEntry())); */
    if (aotmode != 1) { // JIT or Function AOT mode
        InitializeFunction(Entry);
    }
    for (auto &block : *TU) {
        assert(TU->size() && "TU size is expected to be non-zero!");
        if (aotmode == 1) {
            std::stringstream ss;
            ss << std::hex << block.GetBlockEntry() << "." << std::dec
               << block.GetBlockPCSize();
            InitializeFunction(ss.str());
            dbgs() << ss.str() << "\n";
        }
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
        /* TransFunc->dump(); */
    }

    // Do translate finalization.
    TranslateFinalize();
}
