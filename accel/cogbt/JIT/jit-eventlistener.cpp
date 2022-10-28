#include "jit-eventlistener.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"

using namespace llvm::object;

void COGBTEventListener::notifyObjectLoaded(
    ObjectKey K, const object::ObjectFile &Obj,
    const RuntimeDyld::LoadedObjectInfo &L) {
    std::vector<std::pair<SymbolRef, uint64_t>> SymVec =
        computeSymbolSizes(Obj);
    for (const std::pair<SymbolRef, uint64_t> &Sym : SymVec) {
        Expected<SymbolRef::Type> SymType = Sym.first.getType();
        if (!SymType || *SymType != SymbolRef::ST_Function)
            continue;

        Expected<StringRef> FuncName = Sym.first.getName();
        Expected<uint64_t> FuncAddr = Sym.first.getAddress();
        if (!FuncName || !FuncAddr)
            continue;

        NI.AddFunc(FuncName->str(), *FuncAddr, Sym.second);
        dbgs() << "add func " << *FuncName << " size " << Sym.second << "\n";
    }
}
