#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm-translator.h"
#include "memory-manager.h"
#include "host-info.h"
#include <memory>
#include <string>

void LLVMTranslator::InitializeTypes() {
    Int8Ty = Type::getInt8Ty(Context);
    Int16Ty = Type::getInt16Ty(Context);
    Int32Ty = Type::getInt32Ty(Context);
    Int64Ty = Type::getInt64Ty(Context);
    VoidTy = Type::getVoidTy(Context);
    Int8PtrTy = Type::getInt8PtrTy(Context);
    Int64PtrTy = Type::getInt64PtrTy(Context);
};

void LLVMTranslator::InitializeModule() {
    Mod.reset(new Module("cogbt", Context));
    RawMod = Mod.get();

#ifdef CONFIG_HOST_X86
    Mod->setTargetTriple("x86_64-pc-linux-gnu");
    Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-"
                       "n8:16:32:64-S128");
#else
    Mod->setTargetTriple("loongarch64-unknown-linux-gnu");
    Mod->setDataLayout("e-m:e-i8:8:32-i16:16:32-i64:64-n32:64-S128");
#endif

    // Some initialization about JIT.
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    // Import external symbols.
    DeclareExternalSymbols();

    // Initialize data structure of converter
    TU = nullptr;
    TransFunc = nullptr;
    for (auto &V : GMRStates)
        V = nullptr;
    for (auto &V : GMRVals)
        V.clear();
    for (auto &V : HostRegValues)
        V = nullptr;
    ExitBB = EntryBB = nullptr;
}

void LLVMTranslator::InitializeBlock(GuestBlock &Block) {
    for (auto &GMRVal : GMRVals)
        GMRVal.clear();
    uint64_t PC = Block.GetBlockEntry();
    CurrBB = BasicBlock::Create(Context, std::to_string(PC), TransFunc, ExitBB);
    if (PC == TU->GetTUEntry()) {
        dyn_cast<BranchInst>(EntryBB->getTerminator())->setSuccessor(0, CurrBB);
    }
    Builder.SetInsertPoint(CurrBB);
    //debug
    Mod->print(outs(), nullptr);
}

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

void LLVMTranslator::Optimize() {
    legacy::FunctionPassManager FPM(Mod.get());
    legacy::PassManager MPM;

    PassManagerBuilder Builder;
    Builder.OptLevel = 2;
    Builder.LoopVectorize = true;
    Builder.SLPVectorize = true;
    Builder.populateFunctionPassManager(FPM);
    Builder.populateModulePassManager(MPM);
    FPM.doInitialization();
    FPM.run(*TransFunc);
    FPM.doFinalization();

    MPM.run(*Mod.get());
}

void LLVMTranslator::CreateJIT() {
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
    /// EE->RegisterJITEventListener(Listener);

    // Bind addresses to external symbols.
}

void LLVMTranslator::DeleteJIT() {
    EE->removeModule(RawMod);
    delete EE;
}

uint8_t *LLVMTranslator::Compile(bool UseOptmizer) {
    if (UseOptmizer) {
        Optimize();
    }
    //debug
    Mod->print(outs(), nullptr); //debug
    assert(TransFunc && "No translation function in module.");
    CreateJIT();
    uint8_t * FuncAddr = (uint8_t *)EE->getPointerToFunction(TransFunc);
    DeleteJIT();
    return FuncAddr;
}

