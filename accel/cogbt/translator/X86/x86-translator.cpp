#include "llvm/IR/InlineAsm.h"
#include "x86-translator.h"
#include "host-info.h"
#include "emulator.h"

const char *X86Translator::GuestRegNames[NumX64MappedRegs] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

const int X86Translator::GuestRegsToHost[NumX64MappedRegs] = {
    T3, T6, T7, S3, S4, S5, S6, S7,
    S1, S8, A6, A7, T0, T1, T2, S0,
};
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
    for (int i = 0; i < NumX64MappedRegs; i++) {
        GuestStates.push_back(Builder.CreateAlloca(
            Int64Ty, nullptr, StringRef(GuestRegNames[i])));
    }

    // Bind all host physical registers to llvm value.
    for (int i = 0; i < NumHostRegs; i++) {
        Value *HostRegValue = GetPhysicalRegValue(HostRegNames[i]);
        HostRegValues.push_back(HostRegValue);
    }

    // Store physical register value(a.k.a guest state) into stack object.
    for (int i = 0; i < NumX64MappedRegs; i++) {
        Builder.CreateStore(HostRegValues[GuestRegsToHost[i]], GuestStates[i]);
    }

    // Create exit Block. This block loads values in stack object and sync these
    // values into physical registers.
    ExitBB = BasicBlock::Create(Context, "exit", TransFunc);
    Builder.SetInsertPoint(ExitBB);
    for (int i = 0; i < NumX64MappedRegs; i++) {
        // Load latest guest state values.
        Value *GuestState = Builder.CreateLoad(Int64Ty, GuestStates[i]);

        // Sync these values into mapped host physical registers.
        SetPhysicalRegValue(GuestRegNames[i], GuestState);
    }
}

void X86Translator::GenPrologue() {
    InitializeModule();

    FunctionType *FuncTy = FunctionType::get(VoidTy, false);
    TransFunc = Function::Create(FuncTy, Function::ExternalLinkage,
                                 "prologue", *Mod);

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
    Value *CSRPtrs = Builder.CreateIntToPtr(NewSP, CSRArrayTy);
    for (int i = 0; i < NumHostCSRs; i++) {
        Value *CurrCSRPtr = Builder.CreateGEP(CSRArrayTy, CSRPtrs,
                                              ConstantInt::get(Int64Ty, i));
        Builder.CreateStore(HostRegValues[HostCSRs[i]], CurrCSRPtr);
    }

    // Get transalted code entry and ENV value
    Value *CodeEntry = HostRegValues[HostA0];
    Value *ENV = Builder.CreateBitCast(HostRegValues[HostA1], Int8PtrTy);

    // Load guest state into mapped registers
    Value *GuestVals[NumX64MappedRegs];
    for (int i = 0; i < NumX64MappedRegs; i++) {
        Value *Ptr = Builder.CreateGEP(
            nullptr, ENV, ConstantInt::get(Int64Ty, GuestStateOffset(i)));
        GuestVals[i] = Builder.CreateLoad(Int64Ty, Ptr);
    }

    // Sync GuestVals, ENV, CodeEntry to mapped regs
    for (int i = 0; i < NumX64MappedRegs; i++) {
        SetPhysicalRegValue(HostRegNames[GuestRegsToHost[i]], GuestVals[i]);
    }
    SetPhysicalRegValue("r25", HostRegValues[HostA1]);
    SetPhysicalRegValue("r4", CodeEntry); // $r4 maybe modified, sync it.

    // Jump to CodeEntry
    CodeEntry = GetPhysicalRegValue("r4");
    CodeEntry = Builder.CreateIntToPtr(CodeEntry, FuncTy);
    Builder.CreateCall(FuncTy, CodeEntry);
}
