#include "aot-parser.h"
#include "memory-manager.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/TargetSelect.h"

using namespace llvm::object;
using namespace llvm;

AOTParser::AOTParser(uintptr_t CacheBegin, size_t CacheSize, const char *AOT)
    : CodeCache(CacheBegin, CacheSize) {
    if (!AOT) return;

    InitializeAllTargets();
    InitializeAllTargetInfos();
    InitializeAllAsmParsers();
    InitializeAllAsmPrinters();
    InitializeAllTargetMCs();
    InitializeAllDisassemblers();
    InitializeNativeTarget();

    M.reset(new Module("AOT", Ctx));

    std::string ErrorMessage;
    EngineBuilder builder(std::move(M));
    builder.setErrorStr(&ErrorMessage);
    builder.setEngineKind(EngineKind::JIT);
    std::unique_ptr<COGBTMemoryManager> MM(new COGBTMemoryManager(CodeCache));
    builder.setMCJITMemoryManager(std::move(MM));

    EE = builder.create();
    if (!EE) {
        dbgs() << ErrorMessage << "\n";
        llvm_unreachable("Create ExecutionEngine failed");
    }

    // Create AOT object file
    auto obj = object::ObjectFile::createObjectFile(AOT);
    if (!obj) {
        llvm_unreachable("Create AOT object file failed");
    }
    std::unique_ptr<object::ObjectFile> OF(obj->getBinary());

    // Record all function names
    for (SymbolRef Sym : OF->symbols()) {
        Expected<SymbolRef::Type> TypeOrErr = Sym.getType();
        if (!TypeOrErr) {
            llvm_unreachable("Error AOT symbol type");
        }
        if (TypeOrErr.get() != Sym.ST_Function)
            continue;

        Expected<StringRef> NameOrErr = Sym.getName();
        if (!NameOrErr) {
            llvm_unreachable("Error AOT function name");
        }
        FuncNames.push_back(NameOrErr.get());
    }

    // Add this object file to ExecutionEngine and wait for relocation
    EE->addObjectFile(std::move(OF));
}

void AOTParser::AddGlobalMapping(std::string Name, uint64_t Address) {
    EE->addGlobalMapping(Name, Address);
}

void *AOTParser::ParseNextFunction(uint64_t *pc) {
    static std::vector<std::string>::iterator it = FuncNames.begin();
    if (it == FuncNames.end())
        return NULL;
    *pc = std::stol(*it, 0, 16);
    void *Addr = (void *)EE->getFunctionAddress(*it++);
    return Addr;
}

void *AOTParser::GetCurrentCodeCachePtr() {
    return CodeCache.CodeCachePtr;
}
