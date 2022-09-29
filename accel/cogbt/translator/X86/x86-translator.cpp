#include "llvm/IR/InlineAsm.h"
#include "x86-translator.h"
#include "host-info.h"
#include "emulator.h"

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
    GuestStates.resize(GetNumGMRs());
    for (int i = 0; i < GetNumGMRs(); i++) {
        GuestStates[i] =
            Builder.CreateAlloca(Int64Ty, nullptr, GetGMRName(i));
    }

    // Binds all mapped host physical registers with llvm value.
    for (int i = 0; i < GetNumGMRs() - GetNumSpecialGMRs(); i++) {
        Value *HostRegValue =
            GetPhysicalRegValue(HostRegNames[GMRToHMR(i)]);
        HostRegValues[GMRToHMR(i)] = HostRegValue;
    }
    HostRegValues[GMRToHMR(EFLAG)] =
        GetPhysicalRegValue(HostRegNames[GMRToHMR(EFLAG)]);
    CPUEnv = GetPhysicalRegValue(HostRegNames[ENVReg]);
    CPUEnv = Builder.CreateIntToPtr(CPUEnv, Int8PtrTy);

    // Store physical register value(a.k.a guest state) into stack object.
    for (int i = 0; i < GetNumGMRs(); i++) {
        Builder.CreateStore(HostRegValues[GMRToHMR(i)], GuestStates[i]);
    }

    // Create exit Block. This block loads values in stack object and sync these
    // values into physical registers.
    ExitBB = BasicBlock::Create(Context, "exit", TransFunc);
    Builder.SetInsertPoint(ExitBB);
    for (int i = 0; i < GetNumGMRs(); i++) {
        // Load latest guest state values.
        Value *GuestState = Builder.CreateLoad(Int64Ty, GuestStates[i]);

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(HostRegNames[GMRToHMR(i)], GuestState);
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

Value *X86Translator::LoadOperand(X86Operand *Opnd) {
    Type *LLVMTy = GetOpndLLVMType(Opnd);
    X86OperandHandler OpndHdl(Opnd);

    Value *Res = nullptr, *Seg = nullptr, *Base = nullptr, *Index = nullptr;

    if (OpndHdl.isImm()) {
        Res = Builder.CreateAdd(ConstantInt::get(LLVMTy, 0),
                                ConstantInt::get(LLVMTy, Opnd->imm));
    } else if (OpndHdl.isReg()) {
        if (OpndHdl.isGPR()) {
            Res = Builder.CreateLoad(LLVMTy, GuestStates[OpndHdl.GetGMRID()]);
        } else {
            llvm_unreachable("Unhandled register operand type!");
        }
    } else {
        assert(OpndHdl.isMem() && "Opnd type is illegal!");
        // Memory operand has segment register, load its segment base addr.
        if (Opnd->mem.segment != X86_REG_INVALID) {
            Value *Addr = Builder.CreateGEP(
                LLVMTy, CPUEnv,
                ConstantInt::get(Int64Ty, GuestSegOffset(Opnd->mem.segment)));
            Seg = Builder.CreateLoad(Int64Ty, Addr);
            Res = Seg;
        }
        // Base field is valid, calculate base.
        if (Opnd->mem.base != X86_REG_INVALID) {
            int baseReg = OpndHdl.GetGMRID();
            Base = Builder.CreateLoad(Int64Ty, GuestStates[baseReg]);
            if (!Res)
                Res = Base;
            else {
                Res = Builder.CreateAdd(Res, Base);
            }
        }
        // Index field is valid, caculate index*scale.
        if (Opnd->mem.index != X86_REG_INVALID) {
            int indexReg = OpndHdl.GetGMRID();
            int scale = Opnd->mem.scale;
            Index = Builder.CreateLoad(Int64Ty, GuestStates[indexReg]);
            Index = Builder.CreateShl(Index, ConstantInt::get(Int64Ty, scale));
            if (!Res)
                Res = Index;
            else
                Res = Builder.CreateAdd(Res, Index);
        }
        // Disp field is valud, add this offset.
        if (Opnd->mem.disp) {
            Res = Builder.CreateAdd(Res,
                                    ConstantInt::get(Int64Ty, Opnd->mem.disp));
        }
    }
    return Res;
}

void X86Translator::Translate() {
    dbgs() << "Welcome to COGBT translation module!\n";
    InitializeFunction(std::to_string(TU->GetTUEntry()));
    for (auto &block : *TU) {
        for (auto &inst : block) {
            switch (inst->id) {
            default:
                assert(0 && "Unknown x86 opcode!");
#define HANDLE_X86_INST(opcode, name)     \
            case opcode:                  \
                translate_##name();       \
                break;
#include "x86-inst.def"
            }
            /* printf("0x%lx  %s\t%s\n", inst->address, inst->mnemonic, */
            /*         inst->op_str); // debug */
        }
    }
}
