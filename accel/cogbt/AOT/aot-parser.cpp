#include "aot-parser.h"
#include "emulator.h"
#include "memory-manager.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"
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
    auto ObjOrErr = object::ObjectFile::createObjectFile(AOT);
    if (!ObjOrErr) {
        llvm_unreachable("Create AOT object file failed");
    }
    std::unique_ptr<object::ObjectFile> OF(ObjOrErr->getBinary());

    // Create AOT DWARF debug_line table.
    std::unique_ptr<DWARFContext> DCtx =
        DWARFContext::create(*ObjOrErr->getBinary());
    DWARFUnit *Unit = DCtx->getUnitAtIndex(0);
    LT = DCtx->getLineTableForUnit(Unit);

    // Record all function names
    for (ELFSymbolRef Sym : OF->symbols()) {
        Expected<ELFSymbolRef::Type> TypeOrErr = Sym.getType();
        if (!TypeOrErr) {
            llvm_unreachable("Error AOT symbol type");
        }
        if (TypeOrErr.get() != Sym.ST_Function)
            continue;

        Expected<StringRef> NameOrErr = Sym.getName();
        if (!NameOrErr) {
            llvm_unreachable("Error AOT function name");
        }

        Expected<uint64_t> AddrOrErr = Sym.getAddress();
        if (!AddrOrErr) {
            llvm_unreachable("Error AOT function address");
        }
        FuncInfos.emplace_back(NameOrErr.get(), AddrOrErr.get(), Sym.getSize());
    }

    std::sort(FuncInfos.begin(), FuncInfos.end());

    // Add this object file to ExecutionEngine and wait for relocation
    EE->addObjectFile(std::move(OF));
}

void AOTParser::AddGlobalMapping(std::string Name, uint64_t Address) {
    EE->addGlobalMapping(Name, Address);
}

void AOTParser::ResolveSymbols() {
    for (int i = 0; i < SymTableSize; i++)
        EE->addGlobalMapping(SymTable[i].key, (uint64_t)SymTable[i].val);
}

void *AOTParser::ParseNextFunction(uint64_t *pc, size_t *tu_size) {
    static std::vector<FunctionInfo>::iterator it = FuncInfos.begin();
    if (it == FuncInfos.end())
        return NULL;
    const std::string &Name = it->getName();
    *pc = std::stol(Name, 0, 16);
    size_t idx = Name.find('.');
    *tu_size = std::stol(Name.substr(idx + 1));
    void *Addr = (void *)EE->getFunctionAddress(Name);
    ++it;
    return Addr;
}

void *AOTParser::GetCurrentCodeCachePtr() {
    return CodeCache.CodeCachePtr;
}

int AOTParser::FindFunctionInfo(uint64_t HostAddr) {
    int left = 0, right = (int)FuncInfos.size();
    while (left < right) {
        int mid = left + ((right-left) >> 1);
        uint64_t BeginAddr = FuncInfos[mid].getBeginAddr();
        uint64_t EndAddr = FuncInfos[mid].getEndAddr();

        if (HostAddr >=  BeginAddr && HostAddr < EndAddr) { // in range [B, E)
            return mid;
        } else if (HostAddr >= EndAddr) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    assert(left == right && left < (int)FuncInfos.size());
    return left;
}

void AOTParser::RegisterLinkSlot(uint64_t HostAddr, int ExitID, int Type) {
    int idx = FindFunctionInfo(HostAddr);
    FunctionInfo &FI = FuncInfos[idx];
    int offset = HostAddr - FI.getBeginAddr();
    assert(FI.getLinkOffset(ExitID) == -1);
    FI.getLinkOffset(ExitID) = offset;
}

void AOTParser::HandleAllLinkSlots() {
    for (const DWARFDebugLine::Row &R : LT->Rows) {
      R.dump(outs());
    }
}
