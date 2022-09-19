#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm-translator.h"
#include "memory-manager.h"
#include "host-info.h"
#include <memory>
#include <string>

void LLVMTranslator::InitializeModule() {
#ifdef CONFIG_HOST_X86
    Mod->setTargetTriple("x86_64-pc-linux-gnu");
    Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-"
                       "n8:16:32:64-S128");
#else
    Mod->setTargetTriple("loongarch64-unknown-linux-gnu");
    Mod->setDataLayout("e-m:e-i8:8:32-i16:16:32-i64:64-n32:64-S128");
#endif
}


void LLVMTranslator::CreateSession() {
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    std::string ErrorMessage;

    // Set all attributes of an ExecutionEngine.
    EngineBuilder builder(std::move(Mod));
    builder.setErrorStr(&ErrorMessage);
    builder.setEngineKind(EngineKind::JIT);
    std::unique_ptr<COGBTMemoryManager> MM(new COGBTMemoryManager(CodeCache));
    builder.setMCJITMemoryManager(std::move(MM));

    // Create an ExecutionEngine.
    EE = builder.create();
    assert(EE && "ExecutionEngine build error.");

    /// TODO! Register JITEventListener to handle some post-JITed events.
    // EE->RegisterJITEventListener(Listener);

    // Bind addresses to external symbols.
}

void LLVMTranslator::InitializeTypes() {
    Int8Ty = Type::getInt8Ty(Context);
    Int64Ty = Type::getInt64Ty(Context);
    VoidTy = Type::getVoidTy(Context);
    Int8PtrTy = Type::getInt8PtrTy(Context);
    Int64PtrTy = Type::getInt64PtrTy(Context);
};

Value *LLVMTranslator::GetPhysicalRegValue(const char *RegName) {
    // Prepare inline asm type and inline constraints.
    FunctionType *InlineAsmTy = FunctionType::get(Int64Ty, false);
    std::string Constraints(std::string("={") + RegName + "}");

    // Create corresponding inline asm IR.
    InlineAsm *IA = InlineAsm::get(InlineAsmTy, "", Constraints, true);
    Value *HostRegValue = Builder.CreateCall(InlineAsmTy, IA);
    return HostRegValue;
}

void LLVMTranslator::SetPhysicalRegValue(const char *RegName, Value *RegValue) {
    FunctionType *InlineAsmTy = FunctionType::get(VoidTy, Int64Ty, false);
    std::string Constraints = std::string("{") + RegName + "}";
    InlineAsm *IA = InlineAsm::get(InlineAsmTy, "", Constraints, true);
    Builder.CreateCall(InlineAsmTy, IA, {RegValue});
}

uint8_t *LLVMTranslator::Compile(bool UseOptmizer) {
    assert(TransFunc && "No translation function in module.");
    CreateSession();
    return (uint8_t *)EE->getPointerToFunction(TransFunc);
}
