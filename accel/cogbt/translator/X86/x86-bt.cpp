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
            int bit_offset = Opnd0Hdl.getIMM() % (OpndSize << 3);
            index = ConstInt(Int8Ty, bit_offset);
            if (bit_offset >> 3) {
                Value *extraBytes = ConstInt(Int64Ty, bit_offset >> 3);
                base = Builder.CreateAdd(base, extraBytes);
                index = ConstInt(Int8Ty, bit_offset % 8);
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
            // mod 16,32 or 64
            uint64_t mask = (1ULL << __builtin_ctz(OpndSize << 3)) - 1;
            index = Builder.CreateAnd(index, ConstInt(OpndTy, mask));
        }
        // Get index bit of reg
        Value *Src = LoadOperand(InstHdl.getOpnd(1));
        Value *base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(OpndTy, 1));
        if (OpndTy->getIntegerBitWidth() != 64)
            base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = NOT Bit(BitBase, BitOffset)
        Value *Dest = Builder.CreateShl(ConstInt(OpndTy, 1), index);
        Dest = Builder.CreateXor(Src, Dest);
        StoreOperand(Dest, InstHdl.getOpnd(1));
    } else {
        assert(Opnd1Hdl.isMem() && "bt bitbase should be reg or mem");
        Value *index = nullptr;
        Value *base = CalcMemAddr(InstHdl.getOpnd(1));
        if (Opnd0Hdl.isImm()) {
            int bit_offset = Opnd0Hdl.getIMM() % (OpndSize << 3);
            index = ConstInt(Int8Ty, bit_offset);
            if (bit_offset >> 3) {
                Value *extraBytes = ConstInt(Int64Ty, bit_offset >> 3);
                base = Builder.CreateAdd(base, extraBytes);
                index = ConstInt(Int8Ty, bit_offset % 8);
            }
        } else { // index is reg
            index = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
            Value *extraBytes = Builder.CreateAShr(index, ConstInt(Int64Ty, 3));
            base = Builder.CreateAdd(base, extraBytes);
            index = Builder.CreateAnd(index, ConstInt(Int64Ty, 7));
            index = Builder.CreateTrunc(index, Int8Ty);
        }
        // base is int64ty and index is int64ty now.
        Value *MemAddr = Builder.CreateIntToPtr(base, Int8PtrTy);
        Value *Src = Builder.CreateLoad(Int8Ty, MemAddr);
        base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(Int8Ty, 1));
        base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = NOT Bit(BitBase, BitOffset)
        index = Builder.CreateTrunc(index, Int8Ty);
        Value *Dest = Builder.CreateShl(ConstInt(Int8Ty, 1), index);
        Dest = Builder.CreateXor(Builder.CreateZExt(Src, Int8Ty), Dest);
        Builder.CreateStore(Dest, MemAddr);
    }
}

void X86Translator::translate_btr(GuestInst *Inst) {
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
            // mod 16,32 or 64
            uint64_t mask = (1ULL << __builtin_ctz(OpndSize << 3)) - 1;
            index = Builder.CreateAnd(index, ConstInt(OpndTy, mask));
        }
        // Get index bit of reg
        Value *Src = LoadOperand(InstHdl.getOpnd(1));
        Value *base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(OpndTy, 1));
        if (OpndTy->getIntegerBitWidth() != 64)
            base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = 0
        Value *Dest = Builder.CreateShl(ConstInt(OpndTy, 1), index);
        Dest = Builder.CreateXor(Dest, ConstInt(OpndTy, -1));
        Dest = Builder.CreateAnd(Src, Dest);
        StoreOperand(Dest, InstHdl.getOpnd(1));
    } else {
        assert(Opnd1Hdl.isMem() && "bt bitbase should be reg or mem");
        Value *index = nullptr;
        Value *base = CalcMemAddr(InstHdl.getOpnd(1));
        if (Opnd0Hdl.isImm()) {
            int bit_offset = Opnd0Hdl.getIMM() % (OpndSize << 3);
            index = ConstInt(Int8Ty, bit_offset);
            if (bit_offset >> 3) {
                Value *extraBytes = ConstInt(Int64Ty, bit_offset >> 3);
                base = Builder.CreateAdd(base, extraBytes);
                index = ConstInt(Int8Ty, bit_offset % 8);
            }
        } else { // index is reg
            index = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
            Value *extraBytes = Builder.CreateAShr(index, ConstInt(Int64Ty, 3));
            base = Builder.CreateAdd(base, extraBytes);
            index = Builder.CreateAnd(index, ConstInt(Int64Ty, 7));
            index = Builder.CreateTrunc(index, Int8Ty);
        }
        // base is int64ty and index is int64ty now.
        Value *MemAddr = Builder.CreateIntToPtr(base, Int8PtrTy);
        Value *Src = Builder.CreateLoad(Int8Ty, MemAddr);
        base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(Int8Ty, 1));
        base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = 0
        index = Builder.CreateTrunc(index, Int8Ty);
        Value *Dest = Builder.CreateShl(ConstInt(Int8Ty, 1), index);
        Dest = Builder.CreateXor(Dest, ConstInt(Int8Ty, -1));
        Dest = Builder.CreateAnd(Builder.CreateZExt(Src, Int8Ty), Dest);
        Builder.CreateStore(Dest, MemAddr);
    }
}

void X86Translator::translate_bts(GuestInst *Inst) {
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
            // mod 16,32 or 64
            uint64_t mask = (1ULL << __builtin_ctz(OpndSize << 3)) - 1;
            index = Builder.CreateAnd(index, ConstInt(OpndTy, mask));
        }
        // Get index bit of reg
        Value *Src = LoadOperand(InstHdl.getOpnd(1));
        Value *base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(OpndTy, 1));
        if (OpndTy->getIntegerBitWidth() != 64)
            base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = 1
        Value *Dest = Builder.CreateShl(ConstInt(OpndTy, 1), index);
        Dest = Builder.CreateOr(Src, Dest);
        StoreOperand(Dest, InstHdl.getOpnd(1));
    } else {
        assert(Opnd1Hdl.isMem() && "bt bitbase should be reg or mem");
        Value *index = nullptr;
        Value *base = CalcMemAddr(InstHdl.getOpnd(1));
        if (Opnd0Hdl.isImm()) {
            int bit_offset = Opnd0Hdl.getIMM() % (OpndSize << 3);
            index = ConstInt(Int8Ty, bit_offset);
            if (bit_offset >> 3) {
                Value *extraBytes = ConstInt(Int64Ty, bit_offset >> 3);
                base = Builder.CreateAdd(base, extraBytes);
                index = ConstInt(Int8Ty, bit_offset % 8);
            }
        } else { // index is reg
            index = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
            Value *extraBytes = Builder.CreateAShr(index, ConstInt(Int64Ty, 3));
            base = Builder.CreateAdd(base, extraBytes);
            index = Builder.CreateAnd(index, ConstInt(Int64Ty, 7));
            index = Builder.CreateTrunc(index, Int8Ty);
        }
        // base is int64ty and index is int64ty now.
        Value *MemAddr = Builder.CreateIntToPtr(base, Int8PtrTy);
        Value *Src = Builder.CreateLoad(Int8Ty, MemAddr);
        base = Builder.CreateLShr(Src, index);
        base = Builder.CreateAnd(base, ConstInt(Int8Ty, 1));
        base = Builder.CreateZExt(base, Int64Ty);
        SetLBTFlag(base, 0x1);
        // Bit(BitBase, BitOffset) = 1
        Value *Dest = Builder.CreateShl(ConstInt(Int8Ty, 1), index);
        Dest = Builder.CreateOr(Builder.CreateZExt(Src, Int8Ty), Dest);
        Builder.CreateStore(Dest, MemAddr);
    }
}
