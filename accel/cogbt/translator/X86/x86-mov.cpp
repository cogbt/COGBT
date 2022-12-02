#include "x86-translator.h"

void X86Translator::translate_lea(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *V = CalcMemAddr(InstHdl.getOpnd(0));
    StoreOperand(V, InstHdl.getOpnd(1));
}

void X86Translator::translate_mov(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_movabs(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_movd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));

    Value *Src = nullptr, *Dest = nullptr;
    if (SrcOpnd.isXMM() || SrcOpnd.isMMX()) { // Dest must be r/m32
        Src = LoadOperand(InstHdl.getOpnd(0), Int32Ty);
        StoreOperand(Src, InstHdl.getOpnd(1));
    } else if (DestOpnd.isXMM()) {
        Src = LoadOperand(InstHdl.getOpnd(0)); // Src must be r/m32
        Dest = Builder.CreateZExt(Src, Int128Ty);
        StoreOperand(Dest, InstHdl.getOpnd(1));
    } else { // Dest must be mmx
        assert(DestOpnd.isMMX() && "movd dest must be mmx");
        assert(0 && "movd mmx unfinished!");
        // TODO
        /* Src = LoadOperand(InstHdl.getOpnd(0)); // Src must be r/m32 */
    }
}

void X86Translator::translate_movq(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler SrcOpnd(InstHdl.getOpnd(0));
    X86OperandHandler DestOpnd(InstHdl.getOpnd(1));

    Value *Src = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
    Value *Dest = nullptr;
    if (DestOpnd.isXMM()) {
        Dest = Builder.CreateZExt(Src, Int128Ty);
        StoreOperand(Dest, InstHdl.getOpnd(1));
    } else if (DestOpnd.isMMX()) { // Dest must be mmx
        assert(DestOpnd.isMMX() && "movd dest must be mmx");
        assert(0 && "movd mmx unfinished!");
        // TODO
        /* Src = LoadOperand(InstHdl.getOpnd(0)); // Src must be r/m32 */
    } else { // Dest is r/m64
        StoreOperand(Src, InstHdl.getOpnd(1));
    }

}

void X86Translator::translate_movbe(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = nullptr;

    // call llvm.bswap.i16/i32/i64
    FunctionType *FuncTy16 = FunctionType::get(Int16Ty, Int16Ty, false);
    FunctionType *FuncTy32 = FunctionType::get(Int32Ty, Int32Ty, false);
    FunctionType *FuncTy64 = FunctionType::get(Int64Ty, Int64Ty, false);
#if (LLVM_VERSION_MAJOR > 8)
    FunctionCallee F16 = Mod->getOrInsertFunction("llvm.bswap.i16", FuncTy16);
    FunctionCallee F32 = Mod->getOrInsertFunction("llvm.bswap.i32", FuncTy32);
    FunctionCallee F64 = Mod->getOrInsertFunction("llvm.bswap.i64", FuncTy64);
    switch (InstHdl.getOpndSize()) {
    case 2:
        Dest = Builder.CreateCall(F16, Src);
        break;
    case 4:
        Dest = Builder.CreateCall(F32, Src);
        break;
    case 8:
        Dest = Builder.CreateCall(F64, Src);
        break;
    default:
        llvm_unreachable("movbe operand size should be 16/32/64 bits!\n");
    }
#else
    Value *F16 = Mod->getOrInsertFunction("llvm.bswap.i16", FuncTy16);
    Value *F32 = Mod->getOrInsertFunction("llvm.bswap.i32", FuncTy32);
    Value *F64 = Mod->getOrInsertFunction("llvm.bswap.i64", FuncTy64);
    switch (InstHdl.getOpndSize()) {
    case 2:
        Dest = Builder.CreateCall(F16, Src);
        break;
    case 4:
        Dest = Builder.CreateCall(F32, Src);
        break;
    case 8:
        Dest = Builder.CreateCall(F64, Src);
        break;
    default:
        llvm_unreachable("movbe operand size should be 16/32/64 bits!\n");
    }
#endif
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_movddup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movddup\n";
    exit(-1);
}
void X86Translator::translate_movdqa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movdqa\n";
    exit(-1);
}
void X86Translator::translate_movhlps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movhlps\n";
    exit(-1);
}
void X86Translator::translate_movhpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movhpd\n";
    exit(-1);
}
void X86Translator::translate_movhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movhps\n";
    exit(-1);
}
void X86Translator::translate_movlhps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movlhps\n";
    exit(-1);
}
void X86Translator::translate_movlpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movlpd\n";
    exit(-1);
}
void X86Translator::translate_movlps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movlps\n";
    exit(-1);
}
void X86Translator::translate_movmskpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movmskpd\n";
    exit(-1);
}
void X86Translator::translate_movmskps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movmskps\n";
    exit(-1);
}
void X86Translator::translate_movntdqa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntdqa\n";
    exit(-1);
}
void X86Translator::translate_movntdq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntdq\n";
    exit(-1);
}
void X86Translator::translate_movnti(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movnti\n";
    exit(-1);
}
void X86Translator::translate_movntpd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntpd\n";
    exit(-1);
}
void X86Translator::translate_movntps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntps\n";
    exit(-1);
}
void X86Translator::translate_movntsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntsd\n";
    exit(-1);
}
void X86Translator::translate_movntss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movntss\n";
    exit(-1);
}
void X86Translator::translate_movsb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsb\n";
    exit(-1);
}
void X86Translator::translate_movsd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsd\n";
    exit(-1);
}
void X86Translator::translate_movshdup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movshdup\n";
    exit(-1);
}
void X86Translator::translate_movsldup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsldup\n";
    exit(-1);
}
void X86Translator::translate_movsq(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsq\n";
    exit(-1);
}
void X86Translator::translate_movss(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movss\n";
    exit(-1);
}
void X86Translator::translate_movsw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsw\n";
    exit(-1);
}
void X86Translator::translate_movsx(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateSExt(Src0, GetOpndLLVMType(InstHdl.getOpnd(1)));
    StoreOperand(Dest, InstHdl.getOpnd(1));
}
void X86Translator::translate_movsxd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateSExt(Src0, GetOpndLLVMType(InstHdl.getOpnd(1)));
    StoreOperand(Dest, InstHdl.getOpnd(1));
}
void X86Translator::translate_movupd(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movupd\n";
    exit(-1);
}
void X86Translator::translate_movups(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movups\n";
    exit(-1);
}
void X86Translator::translate_movzx(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = Builder.CreateZExt(Src0, GetOpndLLVMType(InstHdl.getOpnd(1)));
    StoreOperand(Dest, InstHdl.getOpnd(1));
}
void X86Translator::translate_mpsadbw(GuestInst *Inst) {
    dbgs() << "Untranslated instruction mpsadbw\n";
    exit(-1);
}

void X86Translator::translate_cmova(GuestInst *Inst) {
    // CF == 0 && ZF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CZ = Builder.CreateAnd(Flag, ConstInt(Int64Ty, CF_BIT | ZF_BIT));
    Value *isZero = Builder.CreateICmpEQ(CZ, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovae(GuestInst *Inst) {
    // CF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, CF_BIT));
    Value *isZero = Builder.CreateICmpEQ(CF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovb(GuestInst *Inst) {
    // CF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, CF_BIT));
    Value *isSet = Builder.CreateICmpNE(CF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovbe(GuestInst *Inst) {
    // CF == 1 OR ZF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *CZ = Builder.CreateAnd(Flag, ConstInt(Int64Ty, CF_BIT | ZF_BIT));
    Value *isSet = Builder.CreateICmpNE(CZ, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmovbe(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovbe\n";
    exit(-1);
}
void X86Translator::translate_fcmovb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovb\n";
    exit(-1);
}

void X86Translator::translate_cmove(GuestInst *Inst) {
    // ZF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, ZF_BIT));
    Value *isSet = Builder.CreateICmpNE(ZF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmove(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmove\n";
    exit(-1);
}

void X86Translator::translate_cmovg(GuestInst *Inst) {
    // ZF == 0 AND SF == OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, ZF_BIT));
    Value *ZFIsZero = Builder.CreateICmpEQ(ZF, ConstInt(Int64Ty, 0));
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *SXorO = Builder.CreateXor(SF, OF);
    Value *SEqualsO = Builder.CreateICmpEQ(SXorO, ConstInt(SXorO->getType(), 0));
    Value *Cond = Builder.CreateAnd(ZFIsZero, SEqualsO);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovge(GuestInst *Inst) {
    // SF == OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *SXorO = Builder.CreateXor(SF, OF);
    Value *SEqualsO = Builder.CreateICmpEQ(SXorO, ConstInt(SXorO->getType(), 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(SEqualsO, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *SXorO = Builder.CreateXor(SF, OF);
    Value *SDiffO = Builder.CreateICmpNE(SXorO, ConstInt(SXorO->getType(), 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(SDiffO, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, ZF_BIT));
    Value *ZFIsSet = Builder.CreateICmpNE(ZF, ConstInt(Int64Ty, 0));
    Value *SF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, SF_SHIFT));
    Value *OF = Builder.CreateLShr(Flag, ConstInt(Int64Ty, OF_SHIFT));
    SF = Builder.CreateAnd(SF, ConstInt(SF->getType(), 1));
    OF = Builder.CreateAnd(OF, ConstInt(OF->getType(), 1));
    Value *SXorO = Builder.CreateXor(SF, OF);
    Value *SDiffO = Builder.CreateICmpNE(SXorO, ConstInt(SXorO->getType(), 0));
    Value *Cond = Builder.CreateOr(ZFIsSet, SDiffO);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmovnbe(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovnbe\n";
    exit(-1);
}
void X86Translator::translate_fcmovnb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovnb\n";
    exit(-1);
}

void X86Translator::translate_cmovne(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // ZF == 0
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, ZF_BIT));
    Value *isZero = Builder.CreateICmpEQ(ZF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmovne(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovne\n";
    exit(-1);
}

void X86Translator::translate_cmovno(GuestInst *Inst) {
    // OF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *OF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, OF_BIT));
    Value *isZero = Builder.CreateICmpEQ(OF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovnp(GuestInst *Inst) {
    // PF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *PF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, PF_BIT));
    Value *isZero = Builder.CreateICmpEQ(PF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmovnu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovnu\n";
    exit(-1);
}

void X86Translator::translate_cmovns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, SF_BIT));
    Value *isZero = Builder.CreateICmpEQ(SF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isZero, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovo(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *OF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, OF_BIT));
    Value *isSet = Builder.CreateICmpNE(OF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovp(GuestInst *Inst) {
    // PF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *PF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, PF_BIT));
    Value *isSet = Builder.CreateICmpNE(PF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_fcmovu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovu\n";
    exit(-1);
}

void X86Translator::translate_cmovs(GuestInst *Inst) {
    // SF == 1
    X86InstHandler InstHdl(Inst);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *SF = Builder.CreateAnd(Flag, ConstInt(Int64Ty, SF_BIT));
    Value *isSet = Builder.CreateICmpNE(SF, ConstInt(Int64Ty, 0));

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(isSet, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmpxchg16b(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpxchg16b\n";
    exit(-1);
}

// FIXME! This implementation is not thread safe.
void X86Translator::translate_cmpxchg(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *SuccBB = BasicBlock::Create(Context, "succ", TransFunc, ExitBB);
    BasicBlock *FailBB = BasicBlock::Create(Context, "fail", TransFunc, SuccBB);
    BasicBlock *JoinBB = BasicBlock::Create(Context, "Join", TransFunc, FailBB);

    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    Value *Src1 = LoadOperand(InstHdl.getOpnd(1));
    Value *Accumulator = LoadGMRValue(Src1->getType(), X86Config::RAX);
    Value *CmpRes = Builder.CreateSub(Accumulator, Src1);
    Value *isSame = Builder.CreateICmpEQ(Accumulator, Src1);
    // Sync all dirty GMRValues into GMRStates.
    SyncAllGMRValue();
    Builder.CreateCondBr(isSame, SuccBB, FailBB);

    Builder.SetInsertPoint(SuccBB);
    // Move Src to Dest
    StoreOperand(Src0, InstHdl.getOpnd(1));
    SyncAllGMRValue();
    Builder.CreateBr(JoinBB);

    Builder.SetInsertPoint(FailBB);
    // Move Dest to Accumulator
    StoreGMRValue(Src1, X86Config::RAX);
    SyncAllGMRValue();
    Builder.CreateBr(JoinBB);

    Builder.SetInsertPoint(JoinBB);
    CalcEflag(Inst, CmpRes, Src1, Accumulator);
}

void X86Translator::translate_cmpxchg8b(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmpxchg8b\n";
    exit(-1);
}
