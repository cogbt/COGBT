#ifndef JIT_EVENTLISTENER_H
#define JIT_EVENTLISTENER_H

#include "llvm-translator.h"
#include "llvm/ExecutionEngine/JITEventListener.h"

using namespace llvm;

//===----------------------------------------------------------------------===//
// LLVM MCJIT Notification infomation definition
//===----------------------------------------------------------------------===//
class JITNotificationInfo {
    std::map<StringRef, std::pair<uint64_t, uint64_t>> FuncNameToAddrSize;
    size_t TotalCodeSize;      ///< Translated host code size of TU.
public:
    JITNotificationInfo() : TotalCodeSize(0) {}
    size_t GetTotalSize() { return TotalCodeSize; }
    void AddFunc(StringRef Name, uint64_t Addr, uint64_t Size) {
        FuncNameToAddrSize[Name] = {Addr, Size};
        TotalCodeSize += Size;
    }

    uint64_t GetAddr(StringRef FuncName) {
        return FuncNameToAddrSize[FuncName].first;
    }

    uint64_t GetSize(StringRef FuncName) {
        return FuncNameToAddrSize[FuncName].second;
    }
};

class COGBTEventListener : public JITEventListener {
    JITNotificationInfo &NI;

public:
    COGBTEventListener(JITNotificationInfo &NI) : NI(NI) {}
    virtual void notifyObjectLoaded(ObjectKey K, const object::ObjectFile &Obj,
            const RuntimeDyld::LoadedObjectInfo &L) override;
};
#endif
