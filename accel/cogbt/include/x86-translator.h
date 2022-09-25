#ifndef X86_TRANSLATOR_H
#define X86_TRANSLATOR_H

#include "llvm-translator.h"

class X86Translator final : public LLVMTranslator {
public:
    X86Translator(uintptr_t CacheBegin, size_t CacheSize)
        : LLVMTranslator(CacheBegin, CacheSize) {}

private:
    /// Guest registers that will be mapped
    enum GuestMappedRegs {
        /// X86_64 mapped registers.
        RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
        R8, R9, R10, R11, R12, R13, R14, R15, EFLAG,

        /// Numbers of X86_64 mapped registers.
        NumX64MappedRegs,

        /// X86 mapped registers.
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,

        /// Numbers of X86 mapped registers.
        NumX86MappedRegs,
    };

    /// Host registers that are used to map guest registers
    enum HostMappedRegs {
        T3 = 15, T6 = 18, T7 = 19, S3 = 26, S4 = 27, S5 = 28, S6 = 29, S7 = 30,
        S1 = 24, S8 = 31, A6 = 10, A7 = 11, T0 = 12, T1 = 13, T2 = 14, S0 = 23,
        FP = 22,
    };

    /// Guest registers name
    const static char *GuestRegNames[NumX64MappedRegs];

    /// Guest registers -> Host registers mapping table
    const static int GuestRegsToHost[NumX64MappedRegs];

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

};

#endif
