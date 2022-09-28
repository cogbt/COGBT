#ifndef X86_CONFIG_H
#define X86_CONFIG_H

#include "guest-config.h"

class X86Config : public GuestConfig {
public:
    virtual int GetNumGMRs() override {
        return NumX64MappedRegs;
    }

    virtual const char *GetGMRName(int id) override {
        return X86RegName[id];
    }

    virtual int GMRToHMR(int gid) override {
        return X86RegToHost[gid];
    }

    /// X86 registers that will be mapped
    enum X86MappedRegs {
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

private:
    /// X86 registers name
    const static char *X86RegName[NumX64MappedRegs];

    /// X86 registers -> Host registers mapping table
    const static int X86RegToHost[NumX64MappedRegs];
};

#endif
