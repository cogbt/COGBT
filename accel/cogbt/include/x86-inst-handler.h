#ifndef X86_INST_HANDLER_H
#define X86_INST_HANDLER_H

#include "translation-unit.h"
#include "x86-opnd-handler.h"
#include <capstone.h>

extern "C" bool guest_inst_is_terminator(cs_insn *insn);

#define CF_BIT (1ULL << 0)
#define PF_BIT (1ULL << 2)
#define AF_BIT (1ULL << 4)
#define ZF_BIT (1ULL << 6)
#define SF_BIT (1ULL << 7)
#define OF_BIT (1ULL << 11)
#define DF_BIT (1ULL << 10)

class X86InstHandler {
public:
    X86InstHandler(GuestInst *Inst) : Inst(Inst) {}

    bool CFisDefined();
    bool OFisDefined();
    bool ZFisDefined();
    bool AFisDefined();
    bool PFisDefined();
    bool SFisDefined();

    uint64_t getCFMask() { return ~CF_BIT; }
    uint64_t getPFMask() { return ~PF_BIT; }
    uint64_t getAFMask() { return ~AF_BIT; }
    uint64_t getZFMask() { return ~ZF_BIT; }
    uint64_t getSFMask() { return ~SF_BIT; }
    uint64_t getOFMask() { return ~OF_BIT; }
    uint64_t getDFMask() { return ~DF_BIT; }

    static uint64_t getPFTable() {
        return (uint64_t)PFTable;
    }

    X86Operand *getOpnd(int idx) {
        assert(idx < (int)Inst->detail->x86.op_count);
        return &Inst->detail->x86.operands[idx];
    }

    int getOpndSize() {
        X86OperandHandler OpndHdl(getOpnd(0));
        return OpndHdl.getOpndSize();
    }

    uint64_t getNextPC() {
        return Inst->address + Inst->size;
    }

    bool isTerminator() {
        return guest_inst_is_terminator(Inst);
    }
private:
    GuestInst *Inst;
    static const char PFTable[256];
};
#endif
