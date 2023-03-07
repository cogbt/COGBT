#include "llvm-translator.h"
#include "jit-eventlistener.h"
#include "host-info.h"
#include "emulator.h"
#include "memory-manager.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "CogbtPass.h"
#include <memory>
#include <string>
#include <sstream>

void LLVMTranslator::InitializeTarget() {
    // Initialize the target registry etc.
    InitializeAllTargetInfos();
    InitializeAllTargets();
    InitializeAllTargetMCs();
    InitializeAllAsmParsers();
    InitializeAllAsmPrinters();

    // Initialize TargetTriple.
#if 0
    TargetTriple = llvm::sys::getDefaultTargetTriple();
#else
    TargetTriple = "loongarch64-unknown-linux-gnu";
#endif

    // Initialize TheTarget.
    std::string Error;
    TheTarget = TargetRegistry::lookupTarget(TargetTriple, Error);
    if (!TheTarget) {
        llvm_unreachable(Error.c_str());
    }

    // Initialize TM.
    TargetOptions opt;
    auto RM = Optional<Reloc::Model>();
    TM = TheTarget->createTargetMachine(TargetTriple, "", "", opt, RM);
}

void LLVMTranslator::InitializeTypes() {
    Int1Ty = Type::getInt1Ty(Context);
    Int8Ty = Type::getInt8Ty(Context);
    Int16Ty = Type::getInt16Ty(Context);
    Int32Ty = Type::getInt32Ty(Context);
    Int64Ty = Type::getInt64Ty(Context);
    Int128Ty = Type::getInt128Ty(Context);
    Int256Ty = Type::getIntNTy(Context, 256);
    Int512Ty = Type::getIntNTy(Context, 512);
    VoidTy = Type::getVoidTy(Context);
    Int8PtrTy = Type::getInt8PtrTy(Context);
    Int16PtrTy = Type::getInt16PtrTy(Context);
    Int32PtrTy = Type::getInt32PtrTy(Context);
    Int64PtrTy = Type::getInt64PtrTy(Context);
    Int128PtrTy = Type::getIntNPtrTy(Context, 128);
    Int80Ty = Type::getIntNTy(Context, 80);
    Int80PtrTy = Type::getIntNPtrTy(Context, 80);
    CPUX86StatePtrTy = StructType::create(Context)->getPointerTo();
};

void LLVMTranslator::AttachLinkInfoToIR(Instruction *I, LIType Type,
        unsigned int Val) {
    DISubprogram *DISP = I->getParent()->getParent()->getSubprogram();
    DILocation *DILoc = DILocation::get(Context, Val, Type, DISP);
    I->setDebugLoc(DILoc);
    /* if (!DIGV) { */
    /*     DIGV = DIB->createGlobalVariableExpression(DISP, "linkslot", "linkslot", */
    /*             DIF, 1, DIB->createNullPtrType(), false); */
    /* } */
    /* I->setMetadata("dbg", DIGV); */
}

void LLVMTranslator::InitializeModule() {
    Mod.reset(new Module("cogbt", Context));
    RawMod = Mod.get();

/* #ifdef CONFIG_HOST_X86 */
/*     Mod->setTargetTriple("x86_64-pc-linux-gnu"); */
/*     Mod->setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-" */
/*                        "n8:16:32:64-S128"); */
/* #else */
    Mod->setTargetTriple("loongarch64-unknown-linux-gnu");
    Mod->setDataLayout("e-m:e-i8:8:32-i16:16:32-i64:64-n32:64-S128");
/* #endif */
    /* Mod->setTargetTriple(TargetTriple); */
    /* Mod->setDataLayout(TM->createDataLayout()); */

    // Import external symbols.
    DeclareExternalSymbols();

    // Initialize data structure of converter
    TU = nullptr;
    TransFunc = nullptr;
    for (auto &V : GMRStates)
        V = nullptr;
    for (auto &V : GMRVals)
        V.clear();
    ExitBB = EntryBB = CurrBB = nullptr;

    // Initialize DWARF debug info(DICompileUnit). Other info will be set at
    // InitializeFuncion.
    DIB.reset(new DIBuilder(*Mod));
    DIF = DIB->createFile("cogbt", "cogbt");
    /* DIB->createCompileUnit(dwarf::DW_LANG_C99, DIF, "cogbt", false, "", 0); */
    DIB->createCompileUnit(dwarf::DW_LANG_C99, DIF, "cogbt", false, "", 0,
                           StringRef(),
                           DICompileUnit::DebugEmissionKind::LineTablesOnly);

    STy = DIB->createSubroutineType(DIB->getOrCreateTypeArray(nullptr));
#if LLVM_VERSION_MAJOR > 8
    Mod->addModuleFlag(Module::ModFlagBehavior::Max, "Dwarf Version", 5);
#endif
    Mod->addModuleFlag(Module::ModFlagBehavior::Max, "Debug Info Version", 3);
}

BasicBlock* LLVMTranslator::GetBasicBlock(Function *Func, StringRef Name) {
    for (BasicBlock &BB : *Func)
        if (BB.getName() == Name)
            return &BB;
    return nullptr;
}

BasicBlock* LLVMTranslator::GetOrInsertBasicBlock(Function *Func, StringRef Name,
        BasicBlock *InsertBefore) {
    BasicBlock *BB = GetBasicBlock(Func, Name);
    if (!BB)
        BB = BasicBlock::Create(Context, Name, Func, InsertBefore);
    return BB;
}

void LLVMTranslator::InitializeBlock(GuestBlock &Block) {
    for (auto &GMRVal : GMRVals)
        GMRVal.clear();
    uint64_t PC = Block.GetBlockEntry();
    std::stringstream ss;
    ss << std::hex << PC;
    std::string Name(ss.str());
    if (aotmode == 2) {
        /* CurrBB = GetOrInsertBasicBlock(TransFunc, Name, ExitBB); */
        CurrBB = GetBasicBlock(TransFunc, Name);
        assert(CurrBB && "block does not exist.");
        if (PC == TU->GetTUEntry()) {
            dyn_cast<BranchInst>(EntryBB->getTerminator())->setSuccessor(0,
        CurrBB);
        }
    } else {
        CurrBB = BasicBlock::Create(Context, Name, TransFunc, ExitBB);
        // Translation unit of jit mde or tb aot mode is block.
        dyn_cast<BranchInst>(EntryBB->getTerminator())->setSuccessor(0, CurrBB);
    }
    Builder.SetInsertPoint(CurrBB);
    /* Mod->print(gdbs(), nullptr); */
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

void LLVMTranslator::TranslateFinalize() {
    // Finalize DIBuilder to make debug info correct.
    DIB->finalize();
    // TODO: fix it to work with all modes
    if (aotmode == 2) {
#if 1
        legacy::FunctionPassManager FPM(Mod.get());
        legacy::PassManager MPM;

        PassManagerBuilder Builder;
        Builder.OptLevel = 2;
        Builder.LoopVectorize = true;
        Builder.SLPVectorize = true;
        Builder.populateFunctionPassManager(FPM);
        Builder.populateModulePassManager(MPM);
        MPM.run(*Mod.get());
#else
#endif
        EmitObjectCode();
        /* Mod->print(dbgs(), nullptr); */
    }
}

void LLVMTranslator::Optimize() {
#if 1
    legacy::FunctionPassManager FPM(Mod.get());
    /* legacy::PassManager MPM; */

    PassManagerBuilder Builder;
    Builder.OptLevel = 2;
    Builder.LoopVectorize = true;
    Builder.SLPVectorize = true;
    Builder.populateFunctionPassManager(FPM);
    /* FPM.add(createFlagReductionPass()); */
    /* Builder.populateModulePassManager(MPM); */
    FPM.doInitialization();
    FPM.run(*TransFunc);
    FPM.doFinalization();

    /* MPM.add(createFlagReductionPass()); */
    /* MPM.run(*Mod.get()); */
#else
    legacy::FunctionPassManager FPM(Mod.get());
    FPM.add(createPromoteMemoryToRegisterPass());
    FPM.add(createAggressiveDCEPass());
    FPM.add(createInstructionCombiningPass());
    FPM.doInitialization();
    FPM.run(*TransFunc);
    FPM.doFinalization();
#endif
}

void LLVMTranslator::CreateJIT(JITEventListener *Listener) {
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

    /// Register JITEventListener to handle some post-JITed events.
    EE->RegisterJITEventListener(Listener);
    EE->setProcessAllSections(true);

    // Bind addresses to external symbols.
    if (Epilogue) {
        EE->addGlobalMapping("epilogue", Epilogue);
        AddExternalSyms();
    }
}

void LLVMTranslator::DeleteJIT(JITEventListener *Listener) {
    EE->UnregisterJITEventListener(Listener);
    EE->removeModule(RawMod);
    delete EE;
}

void LLVMTranslator::EmitObjectCode() {
    /* std::stringstream ss; */
    /* ss << std::hex << TU->GetTUEntry(); */
    /* auto Filename(ss.str() + ".o");//"output.o"; */
    std::string s(exec_path);
    std::string Filename(s + ".aot");
    std::error_code EC;
    raw_fd_ostream dest(Filename, EC, sys::fs::OF_None);

    if (EC) {
        errs() << "Could not open file: " << EC.message();
        exit(-1);
    }

    legacy::PassManager pass;
#if LLVM_VERSION_MAJOR > 8
    auto FileType = CGFT_ObjectFile;
#else
    auto FileType = llvm::TargetMachine::CGFT_ObjectFile;
#endif

    if (TM->addPassesToEmitFile(pass, dest, nullptr, FileType)) {
        errs() << "TheTargetMachine can't emit a file of this type";
        exit(-1);
    }

    pass.run(*Mod);
    dest.flush();

    outs() << "Wrote " << Filename << "\n";
}

uint8_t *LLVMTranslator::Compile(bool UseOptmizer) {
    if (DBG.DebugIR()) {
        dbgs() << "+------------------------------------------------+\n";
        dbgs() << "|                 LLVM  IR                       |\n";
        dbgs() << "+------------------------------------------------+\n";
        // TODO: fix debug information
        /* if (aotmode) */
        /*     TransFunc->print(dbgs(), nullptr); */
        /* else */
        /* Mod->print(dbgs(), nullptr); */
        TransFunc->print(dbgs());
    }
    if (UseOptmizer) {
        Optimize();
        if (DBG.DebugIROpt()) {
            dbgs() << "+------------------------------------------------+\n";
            dbgs() << "|                 LLVM  IR  OPT                  |\n";
            dbgs() << "+------------------------------------------------+\n";
            /* if (aotmode) */
            /*     TransFunc->print(dbgs(), nullptr); */
            /* else */
            /* Mod->print(dbgs(), nullptr); */
            TransFunc->print(dbgs());
        }

    }
    // TODO: modify it
    if (aotmode == 2) {
        return nullptr;
    }
    if (aotmode == 1) {
        EmitObjectCode();
        return nullptr;
    }

    assert(TransFunc && "No translation function in module.");
    JITNotificationInfo NI;
    COGBTEventListener Listener(NI);
    CreateJIT(&Listener);
    std::string FuncName(TransFunc->getName());
    uint8_t *FuncAddr = (uint8_t *)EE->getFunctionAddress(FuncName);
    if (TransFunc->getName() == "AOTEpilogue") {
        Epilogue = (uintptr_t)FuncAddr;
        /* dbgs() << "Epilogue addr " << Epilogue << "\n"; //debug */
    }
    //debug
    /* fprintf(stderr, "After compiole, name epilogue is 0x%lx\n", EE->getAddressToGlobalIfAvailable("epilogue")); */
    DeleteJIT(&Listener);

    if (DBG.DebugHostIns()) {
        dbgs() << "+------------------------------------------------+\n";
        dbgs() << "|                 Host Inst                      |\n";
        dbgs() << "+------------------------------------------------+\n";
        HostDisAsm.PrintInst((uint64_t)FuncAddr, NI.GetSize(FuncName),
                             (uint64_t)FuncAddr);
    }
    return FuncAddr;
}

