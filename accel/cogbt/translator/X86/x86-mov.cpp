#include "x86-translator.h"

void X86Translator::translate_lea(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *V = CalcMemAddr(InstHdl.getOpnd(0));
    StoreOperand(V, InstHdl.getOpnd(1));
}

void X86Translator::translate_xchg(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    Value *Dest = LoadOperand(InstHdl.getOpnd(1));
    StoreOperand(Src, InstHdl.getOpnd(1));
    StoreOperand(Dest, InstHdl.getOpnd(0));
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

void X86Translator::translate_movsb(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
    }

    // 1. Store DS:RSI to ES:RDI
    Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateIntToPtr(RSI, Int8PtrTy);
    RDI = Builder.CreateIntToPtr(RDI, Int8PtrTy);
    Value *V = Builder.CreateLoad(RSI);
    Builder.CreateStore(V, RDI);
    // 2. Update RSI, RDI
    Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
    Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
    Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
    RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateSub(RSI, Step);
    RDI = Builder.CreateSub(RDI, Step);
    StoreGMRValue(RSI, X86Config::RSI);
    StoreGMRValue(RDI, X86Config::RDI);

    if (InstHdl.hasRep()) {
        // 3. Update RCX
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    }
}

void X86Translator::translate_movsw(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
    }

    // 1. Store DS:RSI to ES:RDI
    Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateIntToPtr(RSI, Int16PtrTy);
    RDI = Builder.CreateIntToPtr(RDI, Int16PtrTy);
    Value *V = Builder.CreateLoad(RSI);
    Builder.CreateStore(V, RDI);
    // 2. Update RSI, RDI
    Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
    Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
    Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
    RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateSub(RSI, Step);
    RDI = Builder.CreateSub(RDI, Step);
    StoreGMRValue(RSI, X86Config::RSI);
    StoreGMRValue(RDI, X86Config::RDI);

    if (InstHdl.hasRep()) {
        // 3. Update RCX
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    }
}

void X86Translator::translate_movsd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1(InstHdl.getOpnd(1));
    if (Opnd0.isXMM() || Opnd1.isXMM()) {
        Value *Src = LoadOperand(InstHdl.getOpnd(0), Int64Ty);
        StoreOperand(Src, InstHdl.getOpnd(1));
        return;
    }

    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
    }

    // 1. Store DS:RSI to ES:RDI
    Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateIntToPtr(RSI, Int32PtrTy);
    RDI = Builder.CreateIntToPtr(RDI, Int32PtrTy);
    Value *V = Builder.CreateLoad(RSI);
    Builder.CreateStore(V, RDI);
    // 2. Update RSI, RDI
    Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
    Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
    Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
    RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateSub(RSI, Step);
    RDI = Builder.CreateSub(RDI, Step);
    StoreGMRValue(RSI, X86Config::RSI);
    StoreGMRValue(RDI, X86Config::RDI);

    if (InstHdl.hasRep()) {
        // 3. Update RCX
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    }
}

void X86Translator::translate_movsq(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
    }

    // 1. Store DS:RSI to ES:RDI
    Value *RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateIntToPtr(RSI, Int64PtrTy);
    RDI = Builder.CreateIntToPtr(RDI, Int64PtrTy);
    Value *V = Builder.CreateLoad(RSI);
    Builder.CreateStore(V, RDI);
    // 2. Update RSI, RDI
    Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
    Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
    Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
    RSI = LoadGMRValue(Int64Ty, X86Config::RSI);
    RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
    RSI = Builder.CreateSub(RSI, Step);
    RDI = Builder.CreateSub(RDI, Step);
    StoreGMRValue(RSI, X86Config::RSI);
    StoreGMRValue(RDI, X86Config::RDI);

    if (InstHdl.hasRep()) {
        // 3. Update RCX
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    }
}

void X86Translator::translate_movddup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movddup\n";
    exit(-1);
}

void X86Translator::translate_movdqa(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_movhlps(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movhlps\n";
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
void X86Translator::translate_movshdup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movshdup\n";
    exit(-1);
}
void X86Translator::translate_movsldup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movsldup\n";
    exit(-1);
}
void X86Translator::translate_movss(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler Opnd0Hdl(InstHdl.getOpnd(0));
    X86OperandHandler Opnd1Hdl(InstHdl.getOpnd(1));
    // Source operand is xmm register, only move low 32 bit.
    if (Opnd0Hdl.isXMM()) {
        Value *Src = LoadOperand(InstHdl.getOpnd(0), Int32Ty);
        StoreOperand(Src, InstHdl.getOpnd(1));
    } else {
        assert(Opnd0Hdl.isMem() && Opnd1Hdl.isXMM());
        // Source is memory and dest is xmm
        Value *Src = LoadOperand(InstHdl.getOpnd(0), Int32Ty);
        Src = Builder.CreateZExt(Src, Int128Ty);
        StoreOperand(Src, InstHdl.getOpnd(1));
    }
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

void X86Translator::translate_movaps(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_movapd(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0), Int128Ty);
    StoreOperand(Src, InstHdl.getOpnd(1));
}

void X86Translator::translate_movups(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    Value *Src = LoadOperand(InstHdl.getOpnd(0));
    StoreOperand(Src, InstHdl.getOpnd(1));
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
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setja", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovae(GuestInst *Inst) {
    // CF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjae", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovb(GuestInst *Inst) {
    // CF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjb", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovbe(GuestInst *Inst) {
    // CF == 1 OR ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjbe", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmove(GuestInst *Inst) {
    // ZF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setje", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovg(GuestInst *Inst) {
    // ZF == 0 AND SF == OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjg", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

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
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjge", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovl(GuestInst *Inst) {
    // SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjl", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjle", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovne(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    // ZF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjne", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovno(GuestInst *Inst) {
    // OF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjno", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovnp(GuestInst *Inst) {
    // PF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjnp", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovns(GuestInst *Inst) {
    // SF == 0
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjns", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovo(GuestInst *Inst) {
    // OF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjo", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovp(GuestInst *Inst) {
    // PF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjp", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
    StoreOperand(Dest, InstHdl.getOpnd(1));
}

void X86Translator::translate_cmovs(GuestInst *Inst) {
    // SF == 1
    X86InstHandler InstHdl(Inst);
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Func = Mod->getOrInsertFunction("llvm.loongarch.x86setjs", FTy);
    Value *Cond = Builder.CreateTrunc(Builder.CreateCall(FTy, Func), Int1Ty);

    // if condition is satisfied, prepare src value.
    Value *Src0 = LoadOperand(InstHdl.getOpnd(0));
    // if condition is not satisfied, prepare the former value.
    Value *OldV = LoadOperand(InstHdl.getOpnd(1));

    Value *Dest = Builder.CreateSelect(Cond, Src0, OldV);
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

void X86Translator::translate_stosb(GuestInst *Inst) {
    // AL -> (RDI)
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Store AL to ES:RDI
        Value *AL = LoadGMRValue(Int8Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Builder.CreateStore(AL, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Store AL to ES:RDI
        Value *AL = LoadGMRValue(Int8Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int8PtrTy);
        Builder.CreateStore(AL, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 9));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        /* Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX); */
        /* RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1)); */
        /* StoreGMRValue(RCX, X86Config::RCX); */
    }
}

void X86Translator::translate_stosw(GuestInst *Inst) {
    // AX -> (RDI)
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Store AX to ES:RDI
        Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Builder.CreateStore(AX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 2));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Store AX to ES:RDI
        Value *AX = LoadGMRValue(Int16Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int16PtrTy);
        Builder.CreateStore(AX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 8));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 1));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        /* Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX); */
        /* RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1)); */
        /* StoreGMRValue(RCX, X86Config::RCX); */
    }
}

void X86Translator::translate_stosd(GuestInst *Inst) {
    // EAX -> (RDI)
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Store EAX to ES:RDI
        Value *EAX = LoadGMRValue(Int32Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Builder.CreateStore(EAX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Store EAX to ES:RDI
        Value *EAX = LoadGMRValue(Int32Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int32PtrTy);
        Builder.CreateStore(EAX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 7));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 4));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        /* Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX); */
        /* RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1)); */
        /* StoreGMRValue(RCX, X86Config::RCX); */
    }
}

void X86Translator::translate_stosq(GuestInst *Inst) {
    // RAX -> (RDI)
    X86InstHandler InstHdl(Inst);
    BasicBlock *CheckBB = nullptr, *EndBB = nullptr, *LoopBodyBB = nullptr;
    if (InstHdl.hasRep()) {
        CheckBB = BasicBlock::Create(Context, "CheckBB", TransFunc, ExitBB);
        LoopBodyBB = BasicBlock::Create(Context, "LoopBody", TransFunc, ExitBB);
        EndBB = BasicBlock::Create(Context, "EndBB", TransFunc, ExitBB);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(CheckBB);
        // Check ecx to see if it equals zero.
        Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        Value *isZero = Builder.CreateICmpEQ(RCX, ConstInt(Int64Ty, 0));
        SyncAllGMRValue();
        Builder.CreateCondBr(isZero, EndBB, LoopBodyBB);

        Builder.SetInsertPoint(LoopBodyBB);
        // 1. Store RAX to ES:RDI
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Builder.CreateStore(RAX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
        RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1));
        StoreGMRValue(RCX, X86Config::RCX);
        SyncAllGMRValue();
        Builder.CreateBr(CheckBB);

        Builder.SetInsertPoint(EndBB);
    } else {
        // 1. Store EAX to ES:RDI
        Value *RAX = LoadGMRValue(Int64Ty, X86Config::RAX);
        Value *RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateIntToPtr(RDI, Int64PtrTy);
        Builder.CreateStore(RAX, RDI);
        // 2. Update EDI
        Value *DF = LoadGMRValue(Int64Ty, X86Config::EFLAG);
        DF = Builder.CreateAnd(DF, ConstInt(Int64Ty, DF_BIT));
        Value *Step = Builder.CreateLShr(DF, ConstInt(Int64Ty, 6));
        Step = Builder.CreateSub(Step, ConstInt(Int64Ty, 8));
        RDI = LoadGMRValue(Int64Ty, X86Config::RDI);
        RDI = Builder.CreateSub(RDI, Step);
        StoreGMRValue(RDI, X86Config::RDI);
        // 3. Update RCX
        /* Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX); */
        /* RCX = Builder.CreateSub(RCX, ConstInt(Int64Ty, 1)); */
        /* StoreGMRValue(RCX, X86Config::RCX); */
    }
}
