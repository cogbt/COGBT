#ifndef LLVM_TRANSLATOR_H
#define LLVM_TRANSLATOR_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "translation-unit.h"
#include "host-info.h"

using namespace llvm;

//===----------------------------------------------------------------------===//
// Guest to LLVM IR translator definition
//===----------------------------------------------------------------------===//
class LLVMTranslator {
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

    /// Constructor of LLVM Translator with given code cache to fill in.
    LLVMTranslator(uintptr_t CacheBegin, size_t CacheSize)
        : Builder(Context), CodeCache(CacheBegin, CacheSize) {
        InitializeTypes();
        HostRegValues.resize(NumHostRegs);
    }
    virtual ~LLVMTranslator() = default;

    /// InitializeModule - Initialize necessary Module infomation, like
    /// DataLayout, TargetTriple, DataStructures of converter.
    void InitializeModule();

    /// AddTU - Add a TU to translator.
    ///
    /// In original design, translator can only compile one TU at a time. This
    /// constraint makes it hard to compile multiple functions offline and store
    /// them into a ELF image. A good choice is to use a TU vector to cache
    /// them.
    ///
    /// Clients should guarantee InitializeModule is called before using this
    /// function.
    void AddTU(TranslationUnit *TU) {
        TUs.push_back(TU);
    }

    /// GenPrologue - Generates context switching IR instructions to switch
    /// translator to translation code.
    virtual void GenPrologue() = 0;

    /// GenEpilogue - Generates context switching IR instructions to switch
    /// translation code to translator.
    virtual void GenEpilogue() = 0;

    /// Compile - Compile LLVM IR instructions into host machine code. If \p
    /// UseOptimizer is true, optimizations will be performed first.
    uint8_t *Compile(bool UseOptimizer);

protected:
    /// @name Core Member Variables
    LLVMContext Context;
    std::unique_ptr<Module> Mod; ///< Container of all translated IR.
    Module *RawMod;              ///< Raw pointer of Mod.
    SmallVector<TranslationUnit *, 1> TUs; ///< Guest translation units to handle.

    /// @name Guest->IR converter submodule
    Function *TransFunc;         ///< Translation function.
    IRBuilder<> Builder;         ///< Utility for creating IR instructions.
    SmallVector<Value *, 32> GuestStates;  ///< Stack objects for each guest GPRs.
    SmallVector<Value *, 32> HostRegValues; ///< Host physical regs values. 
    BasicBlock *EntryBB;         ///< Entry block of Translation Function.
    BasicBlock *ExitBB;          ///< Exit block of Translation Function.

    /// Basic types that are frequently used.
    Type *Int8Ty, *Int64Ty, *VoidTy, *Int8PtrTy, *Int64PtrTy;

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
    CodeCacheInfo CodeCache;     ///< Per-translator code cache.

    /// CreateJIT - Initialize the JIT session for current translator. Set
    /// various attributes of ExecutionEngine, IR Module and MemoryManager.
    void CreateJIT();

    /// DeleteSession - Finalize the JIT session.
    void DeleteJIT();
};

#endif
