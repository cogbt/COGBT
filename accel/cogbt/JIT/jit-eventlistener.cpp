#include "jit-eventlistener.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"

using namespace llvm::object;

void COGBTEventListener::notifyObjectLoaded(
    ObjectKey K, const object::ObjectFile &Obj,
    const RuntimeDyld::LoadedObjectInfo &L) {
    auto &DebugObj = *L.getObjectForDebug(Obj).getBinary();
    for (const std::pair<SymbolRef, uint64_t> &Sym :
         computeSymbolSizes(DebugObj)) {
        Expected<SymbolRef::Type> SymType = Sym.first.getType();
        if (!SymType || *SymType != SymbolRef::ST_Function)
            continue;

        Expected<StringRef> FuncName = Sym.first.getName();
        Expected<uint64_t> FuncAddr = Sym.first.getAddress();
        if (!FuncName || !FuncAddr)
            continue;

        NI.AddFunc(*FuncName, *FuncAddr, Sym.second);
    }
}
