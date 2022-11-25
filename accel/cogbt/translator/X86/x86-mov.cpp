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

