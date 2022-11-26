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
    dbgs() << "Untranslated instruction movabs\n";
    exit(-1);
}
void X86Translator::translate_movbe(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movbe\n";
    exit(-1);
}
void X86Translator::translate_movddup(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movddup\n";
    exit(-1);
}
void X86Translator::translate_movdqa(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movdqa\n";
    exit(-1);
}
void X86Translator::translate_movdqu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction movdqu\n";
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
    dbgs() << "Untranslated instruction cmova\n";
    exit(-1);
}
void X86Translator::translate_cmovae(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovae\n";
    exit(-1);
}
void X86Translator::translate_cmovb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovb\n";
    exit(-1);
}
void X86Translator::translate_cmovbe(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovbe\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction cmove\n";
    exit(-1);
}
void X86Translator::translate_fcmove(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmove\n";
    exit(-1);
}
void X86Translator::translate_cmovg(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovg\n";
    exit(-1);
}
void X86Translator::translate_cmovge(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovge\n";
    exit(-1);
}
void X86Translator::translate_cmovl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovl\n";
    exit(-1);
}
void X86Translator::translate_cmovle(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovle\n";
    exit(-1);
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
    dbgs() << "Untranslated instruction cmovno\n";
    exit(-1);
}
void X86Translator::translate_cmovnp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovnp\n";
    exit(-1);
}
void X86Translator::translate_fcmovnu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovnu\n";
    exit(-1);
}
void X86Translator::translate_cmovns(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovns\n";
    exit(-1);
}
void X86Translator::translate_cmovo(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovo\n";
    exit(-1);
}
void X86Translator::translate_cmovp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovp\n";
    exit(-1);
}
void X86Translator::translate_fcmovu(GuestInst *Inst) {
    dbgs() << "Untranslated instruction fcmovu\n";
    exit(-1);
}
void X86Translator::translate_cmovs(GuestInst *Inst) {
    dbgs() << "Untranslated instruction cmovs\n";
    exit(-1);
}
