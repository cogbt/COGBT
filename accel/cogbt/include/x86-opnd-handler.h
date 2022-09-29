#ifndef X86_OPND_HANDLER_H
#define X86_OPND_HANDLER_H

#include "llvm/IR/Value.h"
#include "x86.h"

using llvm::LLVMContext;
using llvm::Value;
using llvm::Type;
using X86Operand = struct cs_x86_op;

class X86OperandHandler {
public:
    /// Constructor - Binding the x86 operand to handle.
    X86OperandHandler(X86Operand *Opnd): Opnd(Opnd) {}

    /// GetGMRID - If operand is a x86 mapped register, return its id, otherwise
    /// return -1.
    int GetGMRID();

    /// isImmediate - Judge if Opnd is an immmediate operand.
    bool isImm() {
        return Opnd->type == X86_OP_IMM;
    }

    /// isRegister - Judge if Opnd is a register operand.
    bool isReg() {
        return Opnd->type == X86_OP_REG;
    }

    /// isMem - Judge if Opnd is a memory operand.
    bool isMem() {
        return Opnd->type == X86_OP_MEM;
    }

    /// isGPR - Judge if Opnd is a GPR register.
    bool isGPR();
private:
    X86Operand *Opnd;
};

#endif
