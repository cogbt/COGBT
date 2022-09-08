#ifndef LLVM_TRANSLATOR_H
#define LLVM_TRANSLATOR_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "translation-unit.h"

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

    ///
    LLVMTranslator(TranslationUnit *TU, uintptr_t CacheBegin, size_t CacheSize)
        : Mod(new Module("cogbt", Context)), TU(TU), Builder(Context),
          CodeCache(CacheBegin, CacheSize) {}
    virtual ~LLVMTranslator() = default;

    ///
    bool compile();

protected:
    /// @name Core Member Variables
    LLVMContext Context;
    std::unique_ptr<Module> Mod; ///< Container of all translated IR.
    TranslationUnit *TU;         ///< Guest translation unit to handle.

    /// @name Guest->IR converter submodule
    Function *Func;              ///< Translation function.
    IRBuilder<> Builder;         ///< Utility for creating IR instructions.
    SmallVector<Value *> GuestStates; ///< Stack objects for each guest GPRs.
    BasicBlock *EntryBB;         ///< Entry block of Translation Function.
    BasicBlock *ExitBB;          ///< Exit block of Translation Function.
    /// InitializeModule - Initialize necessary Module infomation, like
    /// DataLayout, TargetTriple.
    void InitializeModule();

    /// InitializeFunction - Initialize the basic framework of the translation
    /// function, such as `entry` block(binding physical register to IR value),
    /// `exit` block(sync modified guest register state into physical register).
    virtual void InitializeFunction(StringRef FuncName) = 0;

    /// @name IR optimization submodule

    /// @name JIT Submodule Of Translator
    ExecutionEngine *EE;
    CodeCacheInfo CodeCache;     ///< Per-translator code cache.

    /// CreateSession - Initialize the JIT session for current translator. Set
    /// various attributes of ExecutionEngine, IR Module and MemoryManager.
    void CreateSession();

    /// DeleteSession - Finalize the JIT session. Free all resources this
    /// session occupies(e.g EE).
    void DeleteSession();
};

#endif
