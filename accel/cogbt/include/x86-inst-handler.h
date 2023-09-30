#ifndef X86_INST_HANDLER_H
#define X86_INST_HANDLER_H

#include "translation-unit.h"
#include "x86-opnd-handler.h"
#include "cogbt.h"
#include <capstone.h>
#include <sstream>

extern "C" bool guest_inst_is_terminator(cs_insn *insn);
extern "C" int aotmode;
extern bool func_tu_inst_is_terminator(cs_insn *insn);

#define CF_SHIFT 0
#define PF_SHIFT 2
#define AF_SHIFT 4
#define ZF_SHIFT 6
#define SF_SHIFT 7
#define OF_SHIFT 11
#define DF_SHIFT 10

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

    /* static uint64_t getPFTable() { */
    /*     return (uint64_t)PFTable; */
    /* } */

    X86Operand *getOpnd(int idx) {
        assert(idx < (int)Inst->guestInst->detail->x86.op_count);
        return &Inst->guestInst->detail->x86.operands[idx];
    }

    int getOpndNum() {
        return Inst->guestInst->detail->x86.op_count;
    }

    int getOpndSize() {
        X86OperandHandler OpndHdl(getOpnd(0));
        return OpndHdl.getOpndSize();
    }

    uint64_t getPC() {
        return Inst->guestInst->address;
    }

    uint64_t getNextPC() {
        return Inst->guestInst->address + Inst->guestInst->size;
    }

    uint64_t getTargetPC() {
        X86Operand *target = getOpnd(0);
        assert(target->type == X86_OP_IMM && "Target PC should be imm.");
        return target->imm;
    }

    bool isTerminator() {
        if (aotmode == TU_AOT)
            return func_tu_inst_is_terminator(Inst->guestInst);
        else
            return guest_inst_is_terminator(Inst->guestInst);
    }

    // Whether this instruction has prefix rep.
    bool hasRep() {
        return Inst->guestInst->detail->x86.prefix[0] != 0;
    }
    bool hasRepe() {
        return Inst->guestInst->detail->x86.prefix[0] == X86_PREFIX_REPE;
    }
    bool hasRepne() {
        return Inst->guestInst->detail->x86.prefix[0] == X86_PREFIX_REPNE;
    }

    // trace
    unsigned int getNumOfTraceTargets() {
       return Inst->getNumOfTraceTargets();
    }

    std::string getTraceTarget(int index) {
        std::stringstream ss;
        ss << std::hex << Inst->getTraceTarget(index);
        return ss.str();
    }

    const char* getMnemonic() {
        return Inst->guestInst->mnemonic;
    }

    const char* getOPStr() {
        return Inst->guestInst->op_str;
    }

private:
    GuestInst *Inst;
    static const char PFTable[256];
};
#endif
