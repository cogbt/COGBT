#ifndef LLVM_TRANSLATOR_H
#define LLVM_TRANSLATOR_H

#include "cogbt-debug.h"
#include "host-info.h"
#include "jit-eventlistener.h"
#include "translation-unit.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;

//===----------------------------------------------------------------------===//
// The value of a GMR during translation.
//===----------------------------------------------------------------------===//
class GMRValue {
    Value *V;   ///< Value of this GMR(guest mapped register).
    bool Dirty; ///< Wether this value is synced with GMRState.
public:
    GMRValue(Value *V = nullptr, bool Dirty = false) : V(V), Dirty(Dirty) {}
    Value *getValue() { return V; }
    void setValue(Value *V) { this->V = V; }
    void setDirty(bool Dirty) { this->Dirty = Dirty; }
    void set(Value *V, bool Dirty) {
        this->V = V;
        this->Dirty = Dirty;
    }
    bool hasValue() { return V != nullptr; }
    bool isDirty() { return Dirty; }
    void clear() {
        V = nullptr;
        Dirty = false;
    }
};

//===----------------------------------------------------------------------===//
// Guest to LLVM IR translator definition
//===----------------------------------------------------------------------===//
struct LLVMTranslator {
public:
    /// Interface for recording code cache allocations.
    class CodeCacheInfo {
    public:
        uint8_t *CodeCacheBegin; ///< Start address of the code cache region.
        size_t CodeCacheSize;    ///< Total size of the code cache.
        uint8_t *CodeCachePtr;   ///< Start address of the remaining code cache.

        CodeCacheInfo(uintptr_t CodeCacheBegin, size_t CodeCacheSize)
            : CodeCacheBegin((uint8_t *)CodeCacheBegin),
              CodeCacheSize(CodeCacheSize),
              CodeCachePtr((uint8_t *)CodeCacheBegin) {}
    };

    /// COGBT debugger
    Debugger DBG;

    /// Constructor of LLVM Translator with given code cache to fill in.
    LLVMTranslator(uintptr_t CacheBegin, size_t CacheSize,
                   const std::string &HostTripleName,
                   const std::string &GuestTripleName)
        : DBG(), Epilogue(0), Builder(Context),
          CodeCache(CacheBegin, CacheSize), HostDisAsm(HostTripleName),
          GuestDisAsm(GuestTripleName) {
      InitializeTypes();
    }
    virtual ~LLVMTranslator() = default;

    /// InitializeModule - Initialize necessary Module infomation, like
    /// DataLayout, TargetTriple, DataStructures of converter.
    void InitializeModule();

    /// InitializeBlock - Initialize block translation environment.
    void InitializeBlock(GuestBlock &Block);

    /// SetTU - Commit TU to be processed to the translator.
    void SetTU(TranslationUnit *TU) { this->TU = TU; }

    /// DeclareExternalSymbols - Declare external symbols in this module so
    /// translator can access functions or data in dbt.
    virtual void DeclareExternalSymbols() = 0;

    /// GenPrologue - Generates context switching IR instructions to switch
    /// translator to translation code.
    virtual void GenPrologue() = 0;

    /// GenEpilogue - Generates context switching IR instructions to switch
    /// translation code to translator.
    virtual void GenEpilogue() = 0;

    /// Translate - Translate guest TU into IRs and append them to Mod.
    virtual void Translate() = 0;

    /// Compile - Compile LLVM IR instructions into host machine code. If \p
    /// UseOptimizer is true, optimizations will be performed first.
    uint8_t *Compile(bool UseOptimizer);

    /// GetCurrentCodeSize - Get the currently used code cache size.
    size_t GetCurrentCodeSize() {
        return CodeCache.CodeCachePtr - CodeCache.CodeCacheBegin;
    }

protected:
    /// @name Core Member Variables
    LLVMContext Context;
    std::unique_ptr<Module> Mod; ///< Container of all translated IR.
    Module *RawMod;              ///< Raw pointer of Mod.
    TranslationUnit *TU;         ///< Guest translation unit to handle.
    uintptr_t Epilogue;          ///< Epilogue code address.

    /// @name Guest->IR converter submodule
    Function *TransFunc;            ///< Translation function.
    IRBuilder<> Builder;            ///< Utility for creating IR instructions.
    std::vector<Value *> GMRStates; ///< Stack objects for each guest GPRs.
    std::vector<GMRValue> GMRVals;  ///< Guest GPRs values.
    BasicBlock *EntryBB;            ///< Entry block of Translation Function.
    BasicBlock *ExitBB;             ///< Exit block of Translation Function.
    BasicBlock *CurrBB;             ///< Current handled block.
    Value *CPUEnv;                  ///< Pointer to CPUX86State.

    /// Basic types that are frequently used.
    Type *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *Int128Ty, *VoidTy, *Int8PtrTy,
        *Int64PtrTy, *CPUX86StatePtrTy;

    /// InitializeTypes - Cache some basic types that are frequently used in
    /// translator.
    void InitializeTypes();

    /// InitializeFunction - Initialize the basic framework of the translation
    /// function, such as `entry` block(binding physical register to IR value),
    /// `exit` block(sync modified guest register state into physical register).
    ///
    /// NOTE! `entry` and `exit` blocks are not complete in this function. They
    /// are missing termination instructions and leave them up to to client to
    /// implement, like jumping to `epilogue` or return translator.
    virtual void InitializeFunction(StringRef FuncName) = 0;

    Value *GetPhysicalRegValue(const char *RegName);

    void SetPhysicalRegValue(const char *RegName, Value *RegValue);

    /// @name IR optimization submodule
    /// Optimize - Add all standard or custom passes into function pass manager
    /// and run them.
    void Optimize();

    /// @name JIT Submodule Of Translator
    ExecutionEngine *EE;
    CodeCacheInfo CodeCache; ///< Per-translator code cache.
    /* JITNotificationInfo NI; */
    /* COGBTEventListener Listener; */

    /// AddExternalSyms - add external symbols address into ExecutionEngine.
    virtual void AddExternalSyms() = 0;

    /// CreateJIT - Initialize the JIT session for current translator. Set
    /// various attributes of ExecutionEngine, IR Module and MemoryManager.
    void CreateJIT(JITEventListener *Listener);

    /// DeleteSession - Finalize the JIT session.
    void DeleteJIT(JITEventListener *Listener);

    /// @name Debug submodule
    Disassembler HostDisAsm;
    Disassembler GuestDisAsm;
};

#endif
