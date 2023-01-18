#include "x86-opnd-handler.h"
#include "x86-config.h"

int X86OperandHandler::NormalizeGuestReg(int GuestRegID) {
    switch (GuestRegID) {
    default:
        llvm_unreachable("Unexpected X86 reg!");

#define HANDLE_REG(name)             \
    case X86_REG_##name##H:          \
    case X86_REG_##name##L:          \
    case X86_REG_##name##X:          \
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

bool X86OperandHandler::isHSubReg() {
    if (Opnd->type != X86_OP_REG) {
        llvm_unreachable("x86 operand is not a reg!");
    }
    switch (Opnd->reg) {
    case X86_REG_AH:
    case X86_REG_BH:
    case X86_REG_CH:
    case X86_REG_DH:
        return true;
    default:
        return false;
    }
}

int X86OperandHandler::GetGMRID() {
    if (Opnd->type != X86_OP_REG) {
        llvm_unreachable("x86 operand is not a reg!");
    }

    return NormalizeGuestReg(Opnd->reg);
}

int X86OperandHandler::GetXMMID() {
    if (Opnd->type != X86_OP_REG)
        return -1;
    switch (Opnd->reg) {
        case X86_REG_XMM0: return 0;
        case X86_REG_XMM1: return 1;
        case X86_REG_XMM2: return 2;
        case X86_REG_XMM3: return 3;
        case X86_REG_XMM4: return 4;
        case X86_REG_XMM5: return 5;
        case X86_REG_XMM6: return 6;
        case X86_REG_XMM7: return 7;
        case X86_REG_XMM8: return 8;
        case X86_REG_XMM9: return 9;
        case X86_REG_XMM10: return 10;
        case X86_REG_XMM11: return 11;
        case X86_REG_XMM12: return 12;
        case X86_REG_XMM13: return 13;
        case X86_REG_XMM14: return 14;
        case X86_REG_XMM15: return 15;
        default:
            return -1;
    }
}

int X86OperandHandler::GetMMXID() {
    if (Opnd->type != X86_OP_REG)
        return -1;
    switch (Opnd->reg) {
        case X86_REG_MM0: return 0;
        case X86_REG_MM1: return 1;
        case X86_REG_MM2: return 2;
        case X86_REG_MM3: return 3;
        case X86_REG_MM4: return 4;
        case X86_REG_MM5: return 5;
        case X86_REG_MM6: return 6;
        case X86_REG_MM7: return 7;
        default:
            return -1;
    }
}

int X86OperandHandler::GetFPRID() {
    if (Opnd->type != X86_OP_REG)
        return -1;
    switch (Opnd->reg) {
        case X86_REG_ST0: return 0;
        case X86_REG_ST1: return 1;
        case X86_REG_ST2: return 2;
        case X86_REG_ST3: return 3;
        case X86_REG_ST4: return 4;
        case X86_REG_ST5: return 5;
        case X86_REG_ST6: return 6;
        case X86_REG_ST7: return 7;
        default:
            return -1;
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
    case X86_REG_##name##X:      \
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

bool X86OperandHandler::isXMM() {
    if (Opnd->type != X86_OP_REG)
        return 0;
    switch (Opnd->reg) {
        case X86_REG_XMM0:
        case X86_REG_XMM1:
        case X86_REG_XMM2:
        case X86_REG_XMM3:
        case X86_REG_XMM4:
        case X86_REG_XMM5:
        case X86_REG_XMM6:
        case X86_REG_XMM7:
        case X86_REG_XMM8:
        case X86_REG_XMM9:
        case X86_REG_XMM10:
        case X86_REG_XMM11:
        case X86_REG_XMM12:
        case X86_REG_XMM13:
        case X86_REG_XMM14:
        case X86_REG_XMM15:
            return 1;
        default:
            return 0;
    }
}

bool X86OperandHandler::isMMX() {
    if (Opnd->type != X86_OP_REG)
        return 0;
    switch (Opnd->reg) {
        case X86_REG_MM0:
        case X86_REG_MM1:
        case X86_REG_MM2:
        case X86_REG_MM3:
        case X86_REG_MM4:
        case X86_REG_MM5:
        case X86_REG_MM6:
        case X86_REG_MM7:
            return 1;
        default:
            return 0;
    }
}

int X86OperandHandler::GetBaseReg() {
    if (Opnd->type != X86_OP_MEM) {
        llvm_unreachable("x86 operand is not a mem opnd!");
    }
    return NormalizeGuestReg(Opnd->mem.base);
}

int X86OperandHandler::GetIndexReg() {
    if (Opnd->type != X86_OP_MEM) {
        llvm_unreachable("x86 operand is not a mem opnd!");
    }
    return NormalizeGuestReg(Opnd->mem.index);
}
