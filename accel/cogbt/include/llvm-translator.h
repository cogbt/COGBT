#ifndef LLVM_TRANSLATOR_H
#define LLVM_TRANSLATOR_H

#include "cogbt-debug.h"
#include "host-info.h"
#include "jit-eventlistener.h"
#include "translation-unit.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

#include "llvm/Target/TargetMachine.h"

#if (LLVM_VERSION_MAJOR > 8)
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/MC/TargetRegistry.h"
#else
#include "llvm/Support/TargetRegistry.h"
#endif

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
// IR attached link information type definition.
//===----------------------------------------------------------------------===//
enum LIType : unsigned {
    /// Zero is the default value of most dwarf information. So we choose a
    /// special value to begin.
    LI_TBLINK = 100,
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
      InitializeTarget();
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

    /// TranslateInitialize - Hook will be executed before translation.
    virtual void TranslateInitialize() {}

    /// Translate - Translate guest TU into IRs and append them to Mod.
    virtual void Translate() = 0;

    /// TranslateFinalize - Hook will be executed after translation.
    virtual void TranslateFinalize();

    /// Compile - Compile LLVM IR instructions into host machine code. If \p
    /// UseOptimizer is true, optimizations will be performed first.
    uint8_t *Compile(bool UseOptimizer);

    /// GetCurrentCodeSize - Get the currently used code cache size.
    size_t GetCurrentCodeSize() {
        return CodeCache.CodeCachePtr - CodeCache.CodeCacheBegin;
    }

    /// IsExitPC - Return true if PC is the TranslationUnit's the last PC.
    bool IsExitPC(uint64_t PC) {
        if (TU->GetTUExit() == PC)
            return true;
        return false;
    }

    /// GetNextSlotNum - A TranslationUnit has multiple ExitPoints, this
    /// function is uesd to get the next number of ExitPoint.
    int GetNextSlotNum() {
        assert(TU);
        return TU->IncLinkSlotNum();
    }

protected:
    /// @name Core Member Variables
    std::string TargetTriple;    ///< LLVM backend target triple.
    const Target *TheTarget;     ///< LLVM backend target.
    TargetMachine *TM;           ///< Machine description cogbt is targeting.
    LLVMContext Context;
    std::unique_ptr<Module> Mod; ///< Container of all translated IR.
    Module *RawMod;              ///< Raw pointer of Mod.
    TranslationUnit *TU;         ///< Guest translation unit to handle.
    uintptr_t Epilogue;          ///< Epilogue code address.

    /// InitializeTarget - Initialize the target of the cogbt backend according
    /// to current machine.
    void InitializeTarget();

    /// @name Guest->IR converter submodule
    Function *TransFunc;            ///< Translation function.
    IRBuilder<> Builder;            ///< Utility for creating IR instructions.
    std::vector<Value *> GMRStates; ///< Stack objects for each guest GPRs.
    std::vector<GMRValue> GMRVals;  ///< Guest GPRs values.
    BasicBlock *EntryBB;            ///< Entry block of Translation Function.
    BasicBlock *ExitBB;             ///< Exit block of Translation Function.
    BasicBlock *CurrBB;             ///< Current handled block.
    Value *CPUEnv;                  ///< Pointer to CPUX86State.

    /// Utility for creating dwarf debug info.
    std::unique_ptr<DIBuilder> DIB; ///< LLVM debug info builder.
    DIFile *DIF;                    ///< Debug info file.
    DISubroutineType *STy;          ///< Debug info subroutine type of function.
    /* DIGlobalVariableExpression* DIGV; */

    /// AttachLinkInfoToIR - Attach some tb link information to the IR. These
    /// information will be retained in the ELF dwarf and we can parse them to
    /// obtain the machine instruction address and link information.
    /// \p I is the instruction will be attached, \p Type is the kind of this
    /// link information and \p Val is the real value.
    void AttachLinkInfoToIR(Instruction *I, LIType Type, unsigned int Val);

    /// Basic types that are frequently used.
    Type *Int1Ty, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *Int128Ty, *Int256Ty,
         *Int512Ty, *VoidTy, *Int8PtrTy, *Int16PtrTy, *Int32PtrTy, *Int64PtrTy,
         *Int128PtrTy, *CPUX86StatePtrTy, *Int80Ty, *Int80PtrTy;

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

    /// CreateIllegalInstruction - Gen an illegal instruction.
    /// It is used when some instruction is not translated,
    /// but must not be executed.
    void CreateIllegalInstruction();

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

    /// @name AOT submodule
    void EmitObjectCode();

    /// GetBasicBlock - Look up the specified block in the Func.
    BasicBlock* GetBasicBlock(Function *Func, StringRef Name);

    /// GetOrInsertBasicBlock - Look up the specified block in the Func.
    /// 1. If it does not exist, create a Block and return it.
    /// 2. Otherwise, return the block which label is Name.
    ///
    /// If a basicblock need to create and the InsertBefore parameter
    /// is specified, the basic block is automatically inserted before
    /// the specified basic block.
    /// Otherwise, it is inserted at the end of the Func
    BasicBlock* GetOrInsertBasicBlock(Function *Func, StringRef Name,
            BasicBlock *InsertBefore = nullptr);
};

#endif
