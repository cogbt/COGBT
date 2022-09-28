#include "x86-opnd-handler.h"
#include "x86-config.h"

int X86OperandHandler::GetGMRID() {
    if (Opnd->type != X86_OP_REG) {
        llvm_unreachable("x86 operand is not a reg!");
    }

    switch (Opnd->reg) {
    default:
        llvm_unreachable("Unexpected X86 reg!");
    case X86_REG_AH:
    case X86_REG_AL:
    case X86_REG_AX:
    case X86_REG_EAX:
    case X86_REG_RAX:
        return X86Config::RAX;
    case X86_REG_BH:
    case X86_REG_BL:
    case X86_REG_BX:
    case X86_REG_EBX:
    case X86_REG_RBX:
        return X86Config::RBX;
    case X86_REG_CH:
    case X86_REG_CL:
    case X86_REG_CX:
    case X86_REG_ECX:
    case X86_REG_RCX:
        return X86Config::RCX;
    case X86_REG_DH:
    case X86_REG_DL:
    case X86_REG_DX:
    case X86_REG_EDX:
    case X86_REG_RDX:
        return X86Config::RDX;
    case X86_REG_SP:
    case X86_REG_SPL:
    case X86_REG_ESP:
    case X86_REG_RSP:
        return X86Config::RSP;
    case X86_REG_BP:
    case X86_REG_BPL:
    case X86_REG_EBP:
    case X86_REG_RBP:
        return X86Config::RBP;
    case X86_REG_SI:
    case X86_REG_SIL:
    case X86_REG_ESI:
    case X86_REG_RSI:
        return X86Config::RSI;
    case X86_REG_DI:
    case X86_REG_DIL:
    case X86_REG_EDI:
    case X86_REG_RDI:
        return X86Config::RDI;
#define HANDLE_REG(name)     \
    case X86_REG_##name##B:  \
    case X86_REG_##name##W:  \
    case X86_REG_##name##D:  \
    case X86_REG_##name: \
        return X86Config::name;

    HANDLE_REG(R8)
    HANDLE_REG(R9)
    HANDLE_REG(R10)
    HANDLE_REG(R11)
    HANDLE_REG(R12)
    HANDLE_REG(R13)
    HANDLE_REG(R14)
    HANDLE_REG(R15)
#undef HANDLE_REG
    }
}
