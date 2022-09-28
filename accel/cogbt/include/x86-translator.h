#ifndef X86_TRANSLATOR_H
#define X86_TRANSLATOR_H

#include "llvm-translator.h"
#include "x86-config.h"
#include "x86-opnd-handler.h"

class X86Translator final : public LLVMTranslator, public X86Config {
public:
    X86Translator(uintptr_t CacheBegin, size_t CacheSize)
        : LLVMTranslator(CacheBegin, CacheSize) {}

private:
    /// InitializeFunction - Initialize the basic framework of the translation
    /// function, such as `entry` block(binding physical register to IR value),
    /// `exit` block(sync modified guest register state into physical register),
    ///
    /// This function implements the initialization of the X86 guest translation
    /// function.
    virtual void InitializeFunction(StringRef FuncName) override;

    virtual void GenPrologue() override;

    virtual void GenEpilogue() override;

    virtual void Translate() override;

    /// @name X86 translate functions.
#define HANDLE_X86_INST(opcode, name) void translate_##name();
#include "x86-inst.def"
#undef HANDLE_X86_INST

    /// GetOpndType - Get the llvm type of x86 operand.
    Type *GetOpndLLVMType(X86Operand *Opnd);

    /// LoadOperand - Generate llvm IRs to load a x86 opernad and return the
    /// loaded value.
    Value *LoadOperand(X86Operand *Opnd);
};

#endif
