#include "llvm/IR/InlineAsm.h"
#include "x86-translator.h"
#include "host-info.h"

const char *X86Translator::GuestRegsName[NumX64MappedRegs] = {
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
    FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Context), false);
    Func = Function::Create(FuncTy, Function::ExternalLinkage, Name, Mod.get());
    Func->setCallingConv(CallingConv::C);
    Func->addFnAttr(Attribute::NoReturn);
    Func->addFnAttr("cogbt");

    // Create entry block. This block allocates stack objects to cache host
    // mapped physical registers, binds physical registers to llvm values and
    // stores these values into corresponding stack objects.
    EntryBB = BasicBlock::Create(Context, "entry", Func);
    Builder.SetInsertPoint(EntryBB);
    // Allocate stack objects for guest mapped registers.
    for (int i = 0; i < NumX64MappedRegs; i++) {
        GuestStates.push_back(Builder.CreateAlloca(
            Type::getInt64Ty(Context), nullptr, StringRef(GuestRegsName[i])));
    }
    // Binding physical registers to llvm values and stores them into stack.
    for (int i = 0; i < NumX64MappedRegs; i++) {
        // Prepare inline asm type.
        FunctionType *InlineAsmTy =
            FunctionType::get(Type::getInt64Ty(Context), false);
        // Prepare inline asm constraints.
        std::string Constraints(std::string("={") + HostRegisterName[i] + "}");

        // Create corresponding inline asm IR.
        InlineAsm *RegInlineAsm =
            InlineAsm::get(InlineAsmTy, "", Constraints, true);
        Value *GuestState = Builder.CreateCall(InlineAsmTy, RegInlineAsm);

        // Store physical register value(a.k.a guest state) into stack object.
        Builder.CreateStore(GuestState, GuestStates[i]);
    }

    // Create exit Block. This block loads values in stack object and sync these
    // values into physical registers.
    ExitBB = BasicBlock::Create(Context, "exit", Func);
    Builder.SetInsertPoint(ExitBB);
    for (int i = 0; i < NumX64MappedRegs; i++) {
        // Load latest guest state values.
        Value *GuestState =
            Builder.CreateLoad(Type::getInt64Ty(Context), GuestStates[i]);

        // Sync these values into mapped host physical registers.
        FunctionType *InlineAsmTy = FunctionType::get(
            Type::getVoidTy(Context), {Type::getInt64Ty(Context)}, false);
        std::string Constraints = std::string("{") + HostRegisterName[i] + "}";
        InlineAsm *RegInlineAsm =
            InlineAsm::get(InlineAsmTy, "", Constraints, true);
        Builder.CreateCall(InlineAsmTy, RegInlineAsm, {GuestState});
    }
}
