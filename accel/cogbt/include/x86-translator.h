#ifndef X86_TRANSLATOR_H
#define X86_TRANSLATOR_H

#include "llvm-translator.h"
#include "x86-config.h"
#include "x86-inst-handler.h"
#include "x86-opnd-handler.h"

class X86Translator final : public LLVMTranslator, public X86Config {
public:
    X86Translator(uintptr_t CacheBegin, size_t CacheSize)
        : LLVMTranslator(
              CacheBegin, CacheSize,
              "loongarch64-pc-linux-gnu",
              "loongarch64-pc-linux-gnu"), CurrInst(nullptr) {
        }
              //"x86_64-pc-linux-gnu") {}

private:
    /// Currently translated instruction.
    GuestInst *CurrInst;

    /// InitializeFunction - Initialize the basic framework of the translation
    /// function, such as `entry` block(binding physical register to IR value),
    /// `exit` block(sync modified guest register state into physical register),
    ///
    /// This function implements the initialization of the X86 guest translation
    /// function.
    virtual void InitializeFunction(StringRef FuncName) override;

    virtual void DeclareExternalSymbols() override;

    virtual void GenPrologue() override;

    virtual void GenEpilogue() override;

    virtual void AddExternalSyms() override;

    virtual void Translate() override;

    /// @name X86 translate functions.
#define HANDLE_X86_INST(opcode, name) void translate_##name(GuestInst *);
#include "x86-inst.def"
#undef HANDLE_X86_INST

    /// ConstInt - Get a integer constant value.
    Value *ConstInt(Type *Ty, uint64_t Val) {
        return ConstantInt::get(Ty, Val);
    }

    /// GetOpndType - Get the llvm type of x86 operand.
    Type *GetOpndLLVMType(X86Operand *Opnd);
    Type *GetOpndLLVMType(int size);

    /// LoadGMRValue - Load the GMR value from GMRStates. If GMRVals have cached
    /// this value, return it directly. Otherwise load it from GMRStates first.
    /// NOTE! \p Ty should be integer type.
    Value *LoadGMRValue(Type *Ty, int GMRId);

    /// StoreGMRValue - Store value V to GMRVals.
    void StoreGMRValue(Value *V, int GMRId);

    /// CalcMemAddr - Generate llvm IRs to calculate memory address of a memory
    /// operand.
    Value *CalcMemAddr(X86Operand *Opnd);

    /// LoadOperand - Generate llvm IRs to load a x86 operand and return the
    /// loaded value.
    Value *LoadOperand(X86Operand *SrcOpnd);

    /// StoreOperand - Generate llvm IRs to store a value into a x86 operand.
    void StoreOperand(Value *val, X86Operand *DestOpnd);

    /// CalcEflag - Generate llvm IRs to define all eflags.
    void CalcEflag(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);

    /// GenCF/OF - Generate llvm IRs to define CF/OF eflag.
    void GenCF(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);
    void GenOF(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);

    /// FlushGMRValue - Sync GMR value into CPUX86State.
    /// ReloadGMRValue - Reload GMR value from CPUX86State.
    void FlushGMRValue(int GMRId);
    void ReloadGMRValue(int GMRId);
};

#endif
