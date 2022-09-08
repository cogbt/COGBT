#include "llvm/IR/InlineAsm.h"
#include "llvm-translator.h"
#include "memory-manager.h"
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
