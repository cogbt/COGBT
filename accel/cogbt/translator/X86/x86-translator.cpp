#include "llvm/IR/InlineAsm.h"
#include "x86-translator.h"
#include "host-info.h"
#include "emulator.h"

void X86Translator::DeclareExternalSymbols() {
    Mod->getOrInsertGlobal("PFTable", ArrayType::get(Int8Ty, 256));
}

void X86Translator::InitializeFunction(StringRef Name) {
    // Create translation function with (void (*)()) type, C calling convention,
    // and cogbt attribute.
    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage, Name, Mod.get());
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
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
        GMRStates[i] =
            Builder.CreateAlloca(Int64Ty, nullptr, GetGMRName(i));
    }

    // Binds all mapped host physical registers with llvm value.
    for (int i = 0; i < GetNumGMRs() - GetNumSpecialGMRs(); i++) {
        Value *GMRVal =
            GetPhysicalRegValue(HostRegNames[GMRToHMR(i)]);
        GMRVals[i].set(GMRVal, false);
    }
    GMRVals[X86Config::EFLAG].set(
            GetPhysicalRegValue(HostRegNames[GMRToHMR(EFLAG)]), true);
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

    // Insert a default branch of EntryBB to ExitBB.
    Builder.SetInsertPoint(EntryBB);
    Builder.CreateBr(ExitBB);

    // Debug
    Mod->print(outs(), nullptr);
}

void X86Translator::GenPrologue() {
    InitializeModule();

    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage,
                                 "prologue", *Mod);
    TransFunc->setCallingConv(CallingConv::C);
    TransFunc->addFnAttr(Attribute::NoReturn);
    TransFunc->addFnAttr("cogbt");

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
    Value *NewSP = Builder.CreateAdd( OldSP, ConstantInt::get(Int64Ty, -256));
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
    Value *CodeEntry = HostRegValues[HostA0];
    Value *ENV = Builder.CreateIntToPtr(HostRegValues[HostA1], Int8PtrTy);

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
    SetPhysicalRegValue("$r22", GuestVals[EFLAG]);
    SetPhysicalRegValue("$r25", HostRegValues[HostA1]);
    SetPhysicalRegValue("$r4", CodeEntry); // $r4 maybe modified, sync it.
    SetPhysicalRegValue("$r3", NewSP);

    // Jump to CodeEntry
    CodeEntry = GetPhysicalRegValue("$r4");
    CodeEntry = Builder.CreateIntToPtr(CodeEntry, FuncTy->getPointerTo());
    Builder.CreateCall(FuncTy, CodeEntry);
    Builder.CreateUnreachable();

    //debug
    Mod->print(outs(), nullptr);
}

void X86Translator::GenEpilogue() {

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

    auto CurrBB = Builder.GetInsertBlock();
    if (!CurrBB->empty()) {
        Builder.SetInsertPoint(&CurrBB->front());
    }

    Value *V = Builder.CreateLoad(Int64Ty, GMRStates[GMRId]);
    GMRVals[GMRId].setValue(V);
    GMRVals[GMRId].setDirty(false);

    Builder.SetInsertPoint(CurrBB);

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
            Value *Addr = Builder.CreateBitCast(GMRStates[GMRId], V->getType());
            Builder.CreateStore(V, Addr);
        }
    }
}

Value *X86Translator::CalcMemAddr(X86Operand *Opnd) {
    X86OperandHandler OpndHdl(Opnd);
    assert(OpndHdl.isMem() && "CalcMemAddr should handle memory operand!");

    Type *LLVMTy = GetOpndLLVMType(Opnd);
    Value *MemAddr = nullptr, *Seg = nullptr, *Base = nullptr, *Index = nullptr;

    // Memory operand has segment register, load its segment base addr.
    if (Opnd->mem.segment != X86_REG_INVALID) {
        Value *Addr = Builder.CreateGEP(
            LLVMTy, CPUEnv,
            ConstantInt::get(Int64Ty, GuestSegOffset(Opnd->mem.segment)));
        Seg = Builder.CreateLoad(Int64Ty, Addr);
        MemAddr = Seg;
    }
    // Base field is valid, calculate base.
    if (Opnd->mem.base != X86_REG_INVALID) {
        int baseReg = OpndHdl.GetGMRID();
        Base = LoadGMRValue(Int64Ty, baseReg);
        if (!MemAddr)
            MemAddr = Base;
        else {
            MemAddr = Builder.CreateAdd(MemAddr, Base);
        }
    }
    // Index field is valid, caculate index*scale.
    if (Opnd->mem.index != X86_REG_INVALID) {
        int indexReg = OpndHdl.GetGMRID();
        int scale = Opnd->mem.scale;
        Index = LoadGMRValue(Int64Ty, indexReg);
        Index = Builder.CreateShl(Index, ConstantInt::get(Int64Ty, scale));
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

    return MemAddr;
}

Value *X86Translator::LoadOperand(X86Operand *Opnd) {
    Type *LLVMTy = GetOpndLLVMType(Opnd);
    X86OperandHandler OpndHdl(Opnd);

    Value *Res = nullptr;

    if (OpndHdl.isImm()) {
        Res = Builder.CreateAdd(ConstantInt::get(LLVMTy, 0),
                                ConstantInt::get(LLVMTy, Opnd->imm));
    } else if (OpndHdl.isReg()) {
        if (OpndHdl.isGPR()) {
            Res = LoadGMRValue(LLVMTy, OpndHdl.GetGMRID());
        } else {
            llvm_unreachable("Unhandled register operand type!");
        }
    } else {
        assert(OpndHdl.isMem() && "Opnd type is illegal!");
        Res = CalcMemAddr(Opnd);
        Res = Builder.CreateLoad(LLVMTy, Res);
    }
    return Res;
}

void X86Translator::StoreOperand(Value *ResVal, X86Operand *DestOpnd) {
    assert(ResVal && "StoreOperand stores an empty value!");
    X86OperandHandler OpndHdl(DestOpnd);
    if (OpndHdl.isGPR()) {
        StoreGMRValue(ResVal, OpndHdl.GetGMRID());
    } else if (OpndHdl.isMem()) {
        Value *MemAddr = CalcMemAddr(DestOpnd);
        if (!ResVal->getType()->isIntegerTy(64)) {
            MemAddr = Builder.CreateIntToPtr(MemAddr, ResVal->getType());
        }
        Builder.CreateStore(ResVal, MemAddr);
    } else {
        llvm_unreachable("Unhandled StoreOperand type!");
    }
}

void X86Translator::CalcEflag(GuestInst *Inst, Value *Dest, Value *Src1,
                              Value *Src2) {
    X86InstHandler InstHdl(Inst);
    if (InstHdl.CFisDefined()) {
        llvm_unreachable("CF undo!");
    }
    if (InstHdl.OFisDefined()) {
        llvm_unreachable("OF undo!");
    }
    if (InstHdl.ZFisDefined()) {
        Value *IsZero = Builder.CreateICmpEQ(Dest, ConstInt(Dest->getType(), 0));
        Value *ZFBit = Builder.CreateSelect(IsZero, ConstInt(Int64Ty, ZF_BIT),
                                            ConstInt(Int64Ty, 0));
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getZFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, ZFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
    }
    if (InstHdl.AFisDefined()) {
        Value *AFBit = Builder.CreateXor(Dest, Builder.CreateXor(Src1, Src2));
        AFBit = Builder.CreateAnd(AFBit, ConstInt(Int64Ty, AF_BIT));
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getAFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, AFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
    }
    if (InstHdl.PFisDefined()) {
        Type *ArrTy = ArrayType::get(Int8Ty, 256);
        Value *PFT = Mod->getGlobalVariable("PFTable");
        Value *Off = Builder.CreateAnd(Dest, ConstInt(Int64Ty, 0xff));
        Value *PFBytePtr =
            Builder.CreateGEP(ArrTy, PFT, {ConstInt(Int64Ty, 0), Off});
        Value *PFByte = Builder.CreateLoad(Int8Ty, PFBytePtr);
        Value *PFBit = Builder.CreateZExt(PFByte, Int64Ty);
        Value *OldEflag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        Value *ClearEflag = Builder.CreateAnd(OldEflag, InstHdl.getPFMask());
        Value *NewEflag = Builder.CreateOr(ClearEflag, PFBit);
        StoreGMRValue(NewEflag, X86Config::EFLAG);
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
    dbgs() << "Welcome to COGBT translation module!\n";
    InitializeFunction(std::to_string(TU->GetTUEntry()));
    for (auto &block : *TU) {
        dbgs() << "TU->size = " << TU->size() << "\n";
        InitializeBlock(block);
        for (auto &inst : block) {
            switch (inst->id) {
            default:
                assert(0 && "Unknown x86 opcode!");
#define HANDLE_X86_INST(opcode, name)     \
            case opcode:                  \
                translate_##name(inst);   \
                break;
#include "x86-inst.def"
            }
            // debug
            printf("0x%lx  %s\t%s\n", inst->address, inst->mnemonic,
                    inst->op_str); // debug
            /* Mod->print(outs(), nullptr); */
            for (auto InstIt = CurrBB->begin(); InstIt != CurrBB->end();
                 InstIt++) {
                InstIt->print(outs(), true);
                printf("\n");
            }
        }
    }
}
