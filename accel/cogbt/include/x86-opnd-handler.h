#ifndef X86_OPND_HANDLER_H
#define X86_OPND_HANDLER_H

#include "llvm/IR/Value.h"
#include "x86.h"

using llvm::LLVMContext;
using llvm::Type;
using llvm::Value;
using X86Operand = struct cs_x86_op;

class X86OperandHandler {
private:
    int NormalizeGuestReg(int GuestRegID);

public:
    /// Constructor - Binding the x86 operand to handle.
    X86OperandHandler(X86Operand *Opnd) : Opnd(Opnd) {}

    /// GetGMRID - If operand is a x86 mapped register, return its id, otherwise
    /// return -1.
    int GetGMRID();

    /// GetXMMID - If operand is a x86 xmm register, return its index(0-15), -1
    /// otherwise.
    int GetXMMID();

    int GetYMMID();

    int GetZMMID();

    /// GetMMXID - If operand is a x86 mmx register, return its index(0-7), -1
    /// otherwise.
    int GetMMXID();

    /// GetFPRID - If operand is a x87 fpu register, return its index(0-7), -1
    /// otherwise.
    int GetFPRID();

    /// GetSTRID - If operand is a x87 fpu st register, return its index(0-7),
    /// -1 otherwise.
    int GetSTRID();

    /// GetBaseReg - If opnd is a memory operand, return the base reg id. -1
    /// otherwise.
    int GetBaseReg();

    /// GetIndexReg - If opnd is a memory operand, return the index reg id. -1
    /// otherwise.
    int GetIndexReg();

    /// isImmediate - Judge if Opnd is an immmediate operand.
    bool isImm() { return Opnd->type == X86_OP_IMM; }

    /// isRegister - Judge if Opnd is a register operand.
    bool isReg() { return Opnd->type == X86_OP_REG; }

    /// isMem - Judge if Opnd is a memory operand.
    bool isMem() { return Opnd->type == X86_OP_MEM; }

    /// isGPR - Judge if Opnd is a GPR register.
    bool isGPR();

    /// isHSubReg - Judge if Opnd is GPR AH,BH,CH,DH,SIH,DIH
    bool isHSubReg();

    /// isXMM - Judge if Opnd is a XMM register.
    bool isXMM();

    bool isYMM();

    bool isZMM();

    /// isMMX - Judeg if Opnd is a MMX register.
    bool isMMX();

    /// isMMX - Judeg if Opnd is a ST register.
    bool isSTR();

    /// isMMX - Judeg if Opnd is a FP register.
    bool isFPR();
    /// getOpndSize - Get the size(in bytes) of Opnd.
    int getOpndSize() { return Opnd->size; }

    /// setOpndSize - Use only in instrucion fnstsw
    void setOpndSize(int size) { Opnd->size = size; }

    /// getIMM - Get imm operand value.
    int64_t getIMM() { return Opnd->imm; }

    X86Operand *getOpnd() { return Opnd; }

private:
    X86Operand *Opnd;
};

#endif
