#include "x86-opnd-handler.h"
#include "x86-config.h"

int X86OperandHandler::GetGMRID() {
    if (Opnd->type != X86_OP_REG) {
        llvm_unreachable("x86 operand is not a reg!");
    }

    switch (Opnd->reg) {
    default:
        llvm_unreachable("Unexpected X86 reg!");

#define HANDLE_REG(name)             \
    case X86_REG_##name##H:          \
    case X86_REG_##name##L:          \
    case X86_REG_E##name##X:         \
    case X86_REG_R##name##X:         \
        return X86Config::R##name##X;

    HANDLE_REG(A)
    HANDLE_REG(B)
    HANDLE_REG(C)
    HANDLE_REG(D)
#undef HANDLE_REG

#define HANDLE_REG(name)             \
    case X86_REG_##name:             \
    case X86_REG_##name##L:          \
    case X86_REG_E##name:            \
    case X86_REG_R##name:            \
        return X86Config::R##name;

    HANDLE_REG(SP)
    HANDLE_REG(BP)
    HANDLE_REG(SI)
    HANDLE_REG(DI)
#undef HANDLE_REG

#define HANDLE_REG(name)             \
    case X86_REG_##name##B:          \
    case X86_REG_##name##W:          \
    case X86_REG_##name##D:          \
    case X86_REG_##name:             \
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

bool X86OperandHandler::isGPR() {
    if (Opnd->type != X86_OP_REG)
        return false;
    switch (Opnd->reg) {
    default:
        return false;
#define HANDLE_REG(name)         \
    case X86_REG_##name##H:      \
    case X86_REG_##name##L:      \
    case X86_REG_E##name##X:     \
    case X86_REG_R##name##X:

    HANDLE_REG(A)
    HANDLE_REG(B)
    HANDLE_REG(C)
    HANDLE_REG(D)
#undef HANDLE_REG

#define HANDLE_REG(name)         \
    case X86_REG_##name:         \
    case X86_REG_##name##L:      \
    case X86_REG_E##name:        \
    case X86_REG_R##name:

    HANDLE_REG(SP)
    HANDLE_REG(BP)
    HANDLE_REG(SI)
    HANDLE_REG(DI)
#undef HANDLE_REG

#define HANDLE_REG(name)         \
    case X86_REG_##name##B:      \
    case X86_REG_##name##W:      \
    case X86_REG_##name##D:      \
    case X86_REG_##name:

    HANDLE_REG(R8)
    HANDLE_REG(R9)
    HANDLE_REG(R10)
    HANDLE_REG(R11)
    HANDLE_REG(R12)
    HANDLE_REG(R13)
    HANDLE_REG(R14)
    HANDLE_REG(R15)
#undef HANDLE_REG
    return true;
    }
}
