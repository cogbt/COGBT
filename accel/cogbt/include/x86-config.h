#ifndef X86_CONFIG_H
#define X86_CONFIG_H

#include "guest-config.h"

class X86Config : public GuestConfig {
public:
    /// X86 registers that will be mapped
    enum X86MappedRegsId {
        MappedRegsBegin = 0,
        /// X86_64 general-purpose mapped registers.
        RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
        R8, R9, R10, R11, R12, R13, R14, R15,
        NumX64NormalMappedRegs = R15,

        /// X86_64 special mapped registers.
        EFLAG,
        NumX64GPRMappedRegs = EFLAG,

        // X86_64 XMM mapped registers._
        XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
        XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
        NumX64XMMMappedRegs = XMM15,

        NumX64MappedRegs,

        /// X86 mapped registers.
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,

        /// Numbers of X86 mapped registers.
        NumX86MappedRegs,
    };

    /// X86 register types
    enum X86RegType {
        X86RegGPRType = 0,
        X86RegXMMType,

        NumX64RegTypes,
    };

    /// Get number of registers.
    virtual int GetNumGMRs() override { return NumX64MappedRegs; }
    int GetNumGPRs() { return NumX64GPRMappedRegs + 1; }
    int GetNumSpecialGPRs() { return NumX64GPRMappedRegs - NumX64NormalMappedRegs; }
    int GetNumGXMMs() { return NumX64XMMMappedRegs - NumX64GPRMappedRegs; }

    /// Get number of register types.
    int GetNumX86RegType() { return NumX64RegTypes; }

    /// Convert X86MappedRegsId -> id
    int X86MappedRegsIdToId(X86MappedRegsId mid) {
        assert(mid >= MappedRegsBegin && mid < NumX64MappedRegs);
        if (mid <= NumX64GPRMappedRegs)
            return mid;
        else
            return mid - XMM0;
    }

    /// Convert X86MappedRegsId -> register type
    X86RegType X86MappedRegsIdToRegTy(X86MappedRegsId mid) {
        assert(mid >= MappedRegsBegin && mid < NumX64MappedRegs);
        if (mid <= NumX64GPRMappedRegs)
            return X86RegGPRType;
        else
            return X86RegXMMType;
    }

    /// Convert id, type -> X86MappedRegsId
    X86MappedRegsId IdToX86MappedRegsId(X86RegType type, int id) {
        assert(id >= 0);
        switch (type) {
            default:
                fprintf(stderr, "unsupported x86 reg type.\n");
                exit(-1);
            case X86RegGPRType:
                assert(id < GetNumGPRs());
                return (X86MappedRegsId) id;
            case X86RegXMMType:
                assert(id < GetNumGXMMs());
                return (X86MappedRegsId) (XMM0 + id);
        }
    }

    /// Get the name of register
    const char *GetGPRName(int gid) {
        assert(gid < GetNumGPRs());
        return X86GPRName[gid];
    }

    const char *GetGXMMName(int gid) {
        assert(gid < GetNumGXMMs());
        return X64XMMRegName[gid];
    }

    const char *GetGRegName(X86RegType type, int gid) {
        switch (type) {
            default:
                fprintf(stderr, "unsupported x86 reg type.\n");
                exit(-1);
            case X86RegGPRType:
                return GetGPRName(gid);
            case X86RegXMMType:
                return GetGXMMName(gid);
        }
    }

    const char *GetGRegName(X86MappedRegsId mid) {
        X86RegType type = X86MappedRegsIdToRegTy(mid);
        int gid = X86MappedRegsIdToId(mid);
        return GetGRegName(type, gid);
    }

    /// GetRegTypeBits - Get bits width of register for specified type.
    int GetRegTypeBits(X86RegType type) {
        assert(type < NumX64RegTypes);
        return RegTypeSize[type];
    }

    /// GetNumRegForType - Get the number of registers for specified type.
    int GetNumRegForType(X86RegType type) {
        switch (type) {
            default:
                fprintf(stderr, "unsupported x86 reg type.\n");
                exit(-1);
            case X86RegGPRType:
                return GetNumGPRs();
            case X86RegXMMType:
                return GetNumGXMMs();
        }
    }

    /// mapping table conversion
    int GPRToHMR(int gid) {
        assert(gid < GetNumGMRs());
        return X86GPRToHost[gid];
    }

    int GXMMToHMR(int gid) {
        assert(gid < GetNumGXMMs());
        return X64XMMRegToHost[gid];
    }

private:
    /// X86 registers name
    const static char *X86GPRName[];

    /// X86 registers -> Host registers mapping table
    const static int X86GPRToHost[];

    /// X86 registers name
    const static char *X64XMMRegName[];

    /// X86 xmm registers -> Host registers mapping table
    const static int X64XMMRegToHost[];

    /// Number of bytes for various reg types
    const static int RegTypeSize[];
};

#endif
