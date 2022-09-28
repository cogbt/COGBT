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

    /// isImmediate - Return true if Opnd is an immmediate.
    bool isImm() {
        return Opnd->type == X86_OP_IMM;
    }

    /// isRegister - Return true if Opnd is a register
    bool isReg() {
        return Opnd->type == X86_OP_REG;
    }

    bool isMem() {
        return Opnd->type == X86_OP_MEM;
    }

    bool isGPR();
private:
    X86Operand *Opnd;
};

#endif
