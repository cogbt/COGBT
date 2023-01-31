#include "x86-translator.h"

void X86Translator::translate_bt(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0Hdl(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1Hdl(InstHdl.getOpnd(1));
    int OpndSize = Opnd1Hdl.getOpndSize();
    Type *OpndTy = GetOpndLLVMType(OpndSize);

    if (Opnd1Hdl.isReg()) {
        Value *index = nullptr;
        if (Opnd0Hdl.isImm()) {
            index = ConstInt(OpndTy, Opnd0Hdl.getIMM() % (OpndSize << 3));
        } else {
            index = LoadOperand(InstHdl.getOpnd(0));
            uint64_t mask = (1ULL << __builtin_ctz(OpndSize << 3)) - 1;
            index = Builder.CreateAnd(index, ConstInt(OpndTy, mask));
        }
        // Get index bit of reg
        Value *base = LoadOperand(InstHdl.getOpnd(1));
        base = Builder.CreateLShr(base, index);
        base = Builder.CreateAnd(base, ConstInt(OpndTy, 1));
        if (OpndTy->getIntegerBitWidth() != 64)
            base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
    } else {
        assert(Opnd1Hdl.isMem() && "bt bitbase should be reg or mem");
        Value *index = nullptr;
        Value *base = CalcMemAddr(InstHdl.getOpnd(1));
        if (Opnd0Hdl.isImm()) {
            index = ConstInt(Int8Ty, Opnd0Hdl.getIMM() % (OpndSize << 3));
            if (Opnd0Hdl.getIMM() >> 3) {
                Value *extraBytes = ConstInt(Int64Ty, Opnd0Hdl.getIMM() >> 3);
                base = Builder.CreateAdd(base, extraBytes);
            }
        } else { // index is reg
            index = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
            Value *extraBytes = Builder.CreateAShr(index, ConstInt(Int64Ty, 3));
            base = Builder.CreateAdd(base, extraBytes);
            index = Builder.CreateAnd(index, ConstInt(Int64Ty, 7));
            index = Builder.CreateTrunc(index, Int8Ty);
        }
        // base is int64ty and index is int8ty now.
        base =
            Builder.CreateLoad(Int8Ty, Builder.CreateIntToPtr(base, Int8PtrTy));
        base = Builder.CreateLShr(base, index);
        base = Builder.CreateAnd(base, ConstInt(Int8Ty, 1));
        base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
    }
}

void X86Translator::translate_btc(GuestInst *Inst) {
    dbgs() << "Untranslated instruction btc\n";
    exit(-1);
}
void X86Translator::translate_btr(GuestInst *Inst) {
    dbgs() << "Untranslated instruction btr\n";
    exit(-1);
}
void X86Translator::translate_bts(GuestInst *Inst) {
    dbgs() << "Untranslated instruction bts\n";
    exit(-1);
}
