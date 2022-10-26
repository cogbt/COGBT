#ifndef JIT_EVENTLISTENER_H
#define JIT_EVENTLISTENER_H

#include "llvm-translator.h"
#include "llvm/ExecutionEngine/JITEventListener.h"

using namespace llvm;

//===----------------------------------------------------------------------===//
// LLVM MCJIT Notification infomation definition
//===----------------------------------------------------------------------===//
class JITNotificationInfo {
    std::map<std::string, std::pair<uint64_t, uint64_t>> FuncNameToAddrSize;
    size_t TotalCodeSize;      ///< Translated host code size of TU.
public:
    JITNotificationInfo() : TotalCodeSize(0) {}
    ~JITNotificationInfo() {}
    size_t GetTotalSize() { return TotalCodeSize; }
    void AddFunc(std::string Name, uint64_t Addr, uint64_t Size) {
        FuncNameToAddrSize[Name] = {Addr, Size};
        TotalCodeSize += Size;
    }

    uint64_t GetAddr(std::string FuncName) {
        return FuncNameToAddrSize[FuncName].first;
    }

    uint64_t GetSize(std::string FuncName) {
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
