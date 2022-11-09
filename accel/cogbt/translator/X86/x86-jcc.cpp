#include "x86-translator.h"
#include "emulator.h"

void X86Translator::translate_jae(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jae\n";
    exit(-1);
}
void X86Translator::translate_ja(GuestInst *Inst) {
    dbgs() << "Untranslated instruction ja\n";
    exit(-1);
}
void X86Translator::translate_jbe(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jbe\n";
    exit(-1);
}
void X86Translator::translate_jb(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jb\n";
    exit(-1);
}
void X86Translator::translate_jcxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jcxz\n";
    exit(-1);
}
void X86Translator::translate_jecxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jecxz\n";
    exit(-1);
}
void X86Translator::translate_je(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    BasicBlock *TargetBB =
        BasicBlock::Create(Context, "target", TransFunc, ExitBB);
    BasicBlock *FallThroughBB =
        BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
    Value *Flag = LoadGMRValue(Int64Ty, X86Config::EFLAG);
    Value *ZFVal =
        Builder.CreateAnd(Flag, ConstInt(Flag->getType(), InstHdl.getZFMask()));
    ZFVal = Builder.CreateICmpEQ(ZFVal, ConstInt(ZFVal->getType(), 0));
    Builder.CreateCondBr(ZFVal, TargetBB, FallThroughBB);

    Builder.SetInsertPoint(FallThroughBB);
    Value *EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), EIPAddr);
    Builder.CreateBr(ExitBB);

    Builder.SetInsertPoint(TargetBB);
    EnvEIP =
        Builder.CreateGEP(Int8Ty, CPUEnv, ConstInt(Int64Ty, GuestEIPOffset()));
    EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getTargetPC()), EIPAddr);
    Builder.CreateBr(ExitBB);
}
void X86Translator::translate_jge(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jge\n";
    exit(-1);
}
void X86Translator::translate_jg(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jg\n";
    exit(-1);
}
void X86Translator::translate_jle(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jle\n";
    exit(-1);
}
void X86Translator::translate_jl(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jl\n";
    exit(-1);
}
void X86Translator::translate_jmp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jmp\n";
    exit(-1);
}
void X86Translator::translate_jne(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jne\n";
    exit(-1);
}
void X86Translator::translate_jno(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jno\n";
    exit(-1);
}
void X86Translator::translate_jnp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jnp\n";
    exit(-1);
}
void X86Translator::translate_jns(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jns\n";
    exit(-1);
}
void X86Translator::translate_jo(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jo\n";
    exit(-1);
}
void X86Translator::translate_jp(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jp\n";
    exit(-1);
}
void X86Translator::translate_jrcxz(GuestInst *Inst) {
    dbgs() << "Untranslated instruction jrcxz\n";
    exit(-1);
}
void X86Translator::translate_js(GuestInst *Inst) {
    dbgs() << "Untranslated instruction js\n";
    exit(-1);
}
