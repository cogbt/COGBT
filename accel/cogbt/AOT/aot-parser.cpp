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
    EE->setProcessAllSections(true);

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
    const DWARFDebugLine::LineTable  *LT = DCtx->getLineTableForUnit(Unit);

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

    // Handle link slots
    for (const DWARFDebugLine::Row &R : LT->Rows) {
        if (!R.IsStmt || R.EndSequence) continue;
        if (R.Column == LI_TBLINK) {
            RegisterLinkSlot(R.Address, R.Line, R.Column);
        }
    }

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

void *AOTParser::ParseNextFunction(uint64_t *pc, size_t *tu_size,
                                   size_t link_slots_offsets[2]) {
    static std::vector<FunctionInfo>::iterator it = FuncInfos.begin();
    if (it == FuncInfos.end())
        return NULL;

    const std::string &Name = it->getName();
    *pc = std::stol(Name, 0, 16);
    it->getEntryPC() = *pc;

    size_t idx = Name.find('.');
    *tu_size = std::stol(Name.substr(idx + 1));

    link_slots_offsets[0] = it->getLinkOffset(0);
    link_slots_offsets[1] = it->getLinkOffset(1);

    void *Addr = (void *)EE->getFunctionAddress(Name);
    it->getLoadAddr() = (uint64_t)Addr;
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

static uint64_t DecodePCFromCogbtExit(uint32_t *Insts) {
    uint64_t pc = 0;
    while (true) {
        uint64_t CurrInst = *Insts;
        if ((CurrInst & 0xfe000000) == 0x14000000) { // lu12i.w
            int64_t si20 = ((int64_t)CurrInst >> 5) & 0xfffff;
            pc |= si20 << 12;
        } else if ((CurrInst & 0xffc00000) == 0x03800000) { // ori
            uint64_t ui12 = (CurrInst >> 10) & 0xfff;
            pc |= ui12;
        } else if ((CurrInst & 0xfe000000) == 0x16000000) { // lu32i.d
            int64_t si20 = ((int64_t)CurrInst >> 5) & 0xfffff;
            pc |= si20 << 32;
        } else if ((CurrInst & 0xffc00000) == 0x03000000) { // lu52i.d
            int64_t si12 = ((int64_t)CurrInst >> 10) & 0xfff;
            pc |= si12 << 52;
        } else {
            break;
        }
        ++Insts;
    }
    return pc;
}

static void EncodeLinkSlot(uint32_t *Inst, int32_t FixUpOffset) {
    uint32_t BInst = *Inst;
    assert(BInst == 0x50000400 && "BInst should be a B instruction");
    BInst = 0x50000000;
    BInst |= (FixUpOffset & 0xffff) << 10;
    BInst |= (FixUpOffset >> 16) & 0x3ff;
    *Inst = BInst;
}

int AOTParser::FindFunctionInfoAtPC(uint64_t pc) {
    int left = 0, right = (int)FuncInfos.size();
    while (left < right) {
        int mid = left + ((right-left) >> 1);
        uint64_t MidPC = FuncInfos[mid].getEntryPC();

        if (pc == MidPC) {
            return mid;
        } else if (pc > MidPC) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    assert(left == right && left < (int)FuncInfos.size());
    return left;
}

void AOTParser::DoLink() {
    for (FunctionInfo &FI : FuncInfos) {
        const std::string &Name = FI.getName();
        uint64_t CurrPC = std::stol(Name, 0, 16);
        for (int i = 0; i < 2; i++) {
            if (!FI.getLoadAddr() || (FI.getLinkOffset(i) == -1))
                continue;
            uint64_t LinkAddr = FI.getLoadAddr() + FI.getLinkOffset(i);
            uint64_t TargetPC =
                DecodePCFromCogbtExit((uint32_t *)(LinkAddr + 4));
            int idx = FindFunctionInfoAtPC(TargetPC);
            FunctionInfo &TargetFI = FuncInfos[idx];
            int32_t FixUpOffset = (TargetFI.getLoadAddr() - LinkAddr) >> 2;
#ifdef CONFIG_COGBT_DEBUG
            dbgs() << format("PC 0x%lx TargetPC 0x%lx FixUpOffset 0x%lx\n",
                             CurrPC, TargetPC, FixUpOffset);
#endif
            EncodeLinkSlot((uint32_t *)LinkAddr, FixUpOffset);
        }
    }
}
