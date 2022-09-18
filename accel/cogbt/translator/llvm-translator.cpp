#include "llvm/IR/InlineAsm.h"
#include "llvm-translator.h"
#include "memory-manager.h"
#include "host-info.h"
#include <memory>
#include <string>

void LLVMTranslator::InitializeModule() {
    Mod->setTargetTriple("x86_64-pc-linux-gnu");
    Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-"
                       "n8:16:32:64-S128");
}

void LLVMTranslator::CreateSession() {
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
    Int64Ty = Type::getInt64Ty(Context);
    VoidTy = Type::getVoidTy(Context);
    Int8PtrTy = Type::getInt8PtrTy(Context);
};

Value *LLVMTranslator::GetPhysicalRegValue(const char *RegName) {
    // Prepare inline asm type.
    FunctionType *InlineAsmTy = FunctionType::get(Int64Ty, false);
    // Prepare inline asm constraints.
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
    return (uint8_t *)EE->getPointerToFunction(TransFunc);
}
