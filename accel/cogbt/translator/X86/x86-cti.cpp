#include "qemu/osdep.h"
#include "x86-translator.h"
#include "emulator.h"
#include "cogbt.h"
#include <sstream>
#include <iostream>

void X86Translator::GenIndirectJmp(Value *GuestTarget) {
    FunctionType *FTy = nullptr;
    Value *Target = nullptr;
    if (aotmode != JIT) {
#ifdef CONFIG_COGBT_JMP_CACHE
        /* find target_pc from cogbt_jmp_cache first */
        Value *JMPCache = Builder.CreateLoad(Int64PtrTy, JMPCacheAddr);
        Value *HostEntry = Builder.CreateGEP(Int64Ty, JMPCache, GuestTarget);
        HostEntry = Builder.CreateBitCast(HostEntry, Int64PtrTy);
        Value *HostTarget = Builder.CreateLoad(Int64Ty, HostEntry);
        /* Value *HostTarget = ConstInt(Int64Ty, 0x400); */
        Value *Cond = Builder.CreateICmpNE(HostTarget, ConstInt(Int64Ty, 0));

        BasicBlock *TargetBB =
            BasicBlock::Create(Context, "target", TransFunc, ExitBB);
        BasicBlock *FallThroughBB =
            BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
        Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

        // Create target block due to target_pc is in cogbt_jmp_cache
        Builder.SetInsertPoint(TargetBB);
        FTy = FunctionType::get(VoidTy, false);
        Target = Builder.CreateIntToPtr(HostTarget, Int8PtrTy);
        Target = Builder.CreateBitCast(Target, FTy->getPointerTo());
        BindPhysicalReg();
        Builder.CreateCall(FTy, Target);
        Builder.CreateUnreachable();

        // Create fallthrough block due to target_pc is not in cogbt_jmp_cache
        Builder.SetInsertPoint(FallThroughBB);
#endif
    }

    // Store guestpc to env
    Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
    Value *EnvEIP = Builder.CreateGEP(Int8Ty, CPUEnv, Off);
    Value *EIPAddr = Builder.CreateBitCast(EnvEIP, Int64PtrTy);
    Builder.CreateStore(GuestTarget, EIPAddr);

    FTy = FunctionType::get(Int8PtrTy, Int8PtrTy, false);
    Target = CallFunc(FTy, "helper_cogbt_lookup_tb_ptr", CPUEnv);
    FTy = FunctionType::get(VoidTy, false);
    Target = Builder.CreateBitCast(Target, FTy->getPointerTo());
    BindPhysicalReg();
    Builder.CreateCall(FTy, Target);
    Builder.CreateUnreachable();
}

void X86Translator::GenJCCExit(GuestInst *Inst, Value *Cond) {
    X86InstHandler InstHdl(Inst);
    if (aotmode == TU_AOT) {    // TU AOT mode
        std::stringstream ss;
        ss << std::hex << InstHdl.getTargetPC();
        std::string TargetPCStr(ss.str());

        ss.str("");
        ss << std::hex << InstHdl.getNextPC();
        std::string NextPCStr(ss.str());

        BasicBlock *TargetPCBB = nullptr, *NextPCBB = nullptr;
        TargetPCBB = GetBasicBlock(TransFunc, TargetPCStr);
        /* assert(TargetPCBB && "targetpc label does not exist."); */
        NextPCBB = GetBasicBlock(TransFunc, NextPCStr);
        /* assert(TargetPCBB && "nextpc label does not exist."); */

        if (TargetPCBB && NextPCBB) {
            Builder.CreateCondBr(Cond, TargetPCBB, NextPCBB);
        } else {
            Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
            uint8_t flag = 0;
#define TARGETPCBB_FLAG  ((uint8_t) (1U << 0))
#define NEXTPCBB_FLAG    ((uint8_t) (1U << 1))
            if (!TargetPCBB) {
                flag |= TARGETPCBB_FLAG;
                TargetPCBB =
                    BasicBlock::Create(Context, "target", TransFunc, ExitBB);
            }
            if (!NextPCBB) {
                flag |= NEXTPCBB_FLAG;
                NextPCBB =
                    BasicBlock::Create(Context, "fallthrough", TransFunc, TargetPCBB);
            }
            /* BindPhysicalReg(); */
            Builder.CreateCondBr(Cond, TargetPCBB, NextPCBB);
            if (flag & TARGETPCBB_FLAG) {
                /* std::cout << "jcc " << TargetPCStr << std::endl; */
                Builder.SetInsertPoint(TargetPCBB);
                BindPhysicalReg();
                Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());
                // Create target link slot
                Instruction *LinkSlot = GetCogbtExitIntrinsic({TargetPC, Off});
                AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
                // Jump back qemu.
                Builder.CreateCall(Mod->getFunction("epilogue"));
                Builder.CreateUnreachable();
            }
            if (flag & NEXTPCBB_FLAG) {
                // Create fallthrough link slot.
                Builder.SetInsertPoint(NextPCBB);
                BindPhysicalReg();
                Value *NextPC = ConstInt(Int64Ty, InstHdl.getNextPC());
                Instruction *LinkSlot = GetCogbtExitIntrinsic({NextPC, Off});
                AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
                // Jump back qemu.
                Builder.CreateCall(Mod->getFunction("epilogue"));
                Builder.CreateUnreachable();
            }
#undef TARGETPCBB_FLAG
#undef NEXTPCBB_FLAG
        }
        if (IsExitPC(InstHdl.getPC())) {
            ExitBB->eraseFromParent();
        }

    } else {  // Tb AOt or JIT mode
        BasicBlock *TargetBB =
            BasicBlock::Create(Context, "target", TransFunc, ExitBB);
        BasicBlock *FallThroughBB =
            BasicBlock::Create(Context, "fallthrough", TransFunc, TargetBB);
        BindPhysicalReg();
        Builder.CreateCondBr(Cond, TargetBB, FallThroughBB);

        Value *Off = ConstInt(Int64Ty, GuestEIPOffset());

        // Create fallthrough link slot.
        Builder.SetInsertPoint(FallThroughBB);
        Value *NextPC = ConstInt(Int64Ty, InstHdl.getNextPC());
        Instruction *LinkSlot = GetCogbtExitIntrinsic({NextPC, Off});
        AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
        // Jump back qemu.
        Builder.CreateCall(Mod->getFunction("epilogue"));
        Builder.CreateUnreachable();

        Builder.SetInsertPoint(TargetBB);
        Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());
        // Create target link slot
        LinkSlot = GetCogbtExitIntrinsic({TargetPC, Off});
        AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
        // Jump back qemu.
        Builder.CreateCall(Mod->getFunction("epilogue"));
        Builder.CreateUnreachable();

        ExitBB->eraseFromParent();
    }
}

void X86Translator::translate_jae(GuestInst *Inst) {
    // CF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjae");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_ja(GuestInst *Inst) {
    // CF == 0 && ZF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setja");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jbe(GuestInst *Inst) {
    // CF == 1 or ZF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjbe");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jb(GuestInst *Inst) {
    // CF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjb");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_je(GuestInst *Inst) {
    // ZF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setje");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jge(GuestInst *Inst) {
    // SF == OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjge");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jg(GuestInst *Inst) {
    // ZF == 0 AND SF == OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjg");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jle(GuestInst *Inst) {
    // ZF == 1 OR SF != OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjle");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jl(GuestInst *Inst) {
    // SF != OF
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjl");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jne(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjne");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jno(GuestInst *Inst) {
    // OF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjno");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jnp(GuestInst *Inst) {
    // PF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjnp");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jns(GuestInst *Inst) {
    // SF == 0
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjns");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jo(GuestInst *Inst) {
    // OF == 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjo");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jp(GuestInst *Inst) {
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjp");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_js(GuestInst *Inst) {
    // SF = 1
    FunctionType *FTy = FunctionType::get(Int32Ty, None, false);
    Value *Val = CallFunc(FTy, "llvm.loongarch.x86setjs");
    Value *Cond = Builder.CreateTrunc(Val, Int1Ty);
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jcxz(GuestInst *Inst) {
    // CX == 0
    Value *CX = LoadGMRValue(Int16Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(CX, ConstInt(CX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jecxz(GuestInst *Inst) {
    // ECX == 0
    Value *ECX = LoadGMRValue(Int32Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(ECX, ConstInt(ECX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jrcxz(GuestInst *Inst) {
    // RCX == 0
    Value *RCX = LoadGMRValue(Int64Ty, X86Config::RCX);
    Value *Cond = Builder.CreateICmpEQ(RCX, ConstInt(RCX->getType(), 0));
    SyncAllGMRValue();
    GenJCCExit(Inst, Cond);
}

void X86Translator::translate_jmp(GuestInst *Inst) {
    SyncAllGMRValue();
    X86InstHandler InstHdl(Inst);
    // Create link here, NOTE! Distinguish direct jmp or indirect jmp first.
    X86OperandHandler OpndHdl(InstHdl.getOpnd(0));
    if (OpndHdl.isImm()) {   // direct jmp
        if (aotmode == TU_AOT) {     // Function AOT mode
            std::stringstream ss;
            ss << std::hex << InstHdl.getTargetPC();
            std::string TargetPCStr(ss.str());

            BasicBlock *TargetBB = GetBasicBlock(TransFunc, TargetPCStr);
            /* assert(TargetBB && "target label does not exist."); */
            /* BindPhysicalReg(); */
            if (TargetBB) {
                Builder.CreateBr(TargetBB);
            } else {    // this label does not in this function, go to epilogue
                Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
                Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());

                BindPhysicalReg();
                Instruction *LinkSlot = GetCogbtExitIntrinsic({TargetPC, Off});
                AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
                Builder.CreateCall(Mod->getFunction("epilogue"));
                Builder.CreateUnreachable();
            }
            if (IsExitPC(InstHdl.getPC())) {
                ExitBB->eraseFromParent();
            }
        } else {    // JIT or TB AOT mode
            Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
            Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());

            BindPhysicalReg();
            Instruction *LinkSlot = GetCogbtExitIntrinsic({TargetPC, Off});
            AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
            Builder.CreateCall(Mod->getFunction("epilogue"));
            Builder.CreateUnreachable();
            ExitBB->eraseFromParent();
        }
    } else {    // indirect jmp
        Value *Target = LoadOperand(InstHdl.getOpnd(0));

        GenIndirectJmp(Target);
        if (IsExitPC(InstHdl.getPC())) {
            ExitBB->eraseFromParent();
        }
    }
}

void X86Translator::translate_call(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);
    X86OperandHandler OpndHdl(InstHdl.getOpnd(0));

    // direct call
    if (OpndHdl.isImm()) {
        // adjust esp
        Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
        Value *NewESP = Builder.CreateSub(OldESP, ConstInt(Int64Ty, 8));
        StoreGMRValue(NewESP, X86Config::RSP);

        // store return address into stack
        Value *NewESPPtr = Builder.CreateIntToPtr(NewESP, Int64PtrTy);
        Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), NewESPPtr);

        // sync GMRVals into stack.
        SyncAllGMRValue();

        // do direct basic block link
        Value *Off = ConstInt(Int64Ty, GuestEIPOffset());
        Value *TargetPC = ConstInt(Int64Ty, InstHdl.getTargetPC());

        BindPhysicalReg();
        Instruction *LinkSlot = GetCogbtExitIntrinsic({TargetPC, Off});
        /* if (aotmode == 2) */
        AttachLinkInfoToIR(LinkSlot, LI_TBLINK, GetNextSlotNum());
        /* else */
        /*     AttachLinkInfoToIR(LinkSlot, LI_TBLINK, 1); */
        Builder.CreateCall(Mod->getFunction("epilogue"));
        Builder.CreateUnreachable();
        if (IsExitPC(InstHdl.getPC())) {
            ExitBB->eraseFromParent();
        }
    } else {
        Value *Target = LoadOperand(InstHdl.getOpnd(0));

        // adjust esp
        Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
        Value *NewESP = Builder.CreateSub(OldESP, ConstInt(Int64Ty, 8));
        StoreGMRValue(NewESP, X86Config::RSP);

        // store return address into stack
        Value *NewESPPtr = Builder.CreateIntToPtr(NewESP, Int64PtrTy);
        Builder.CreateStore(ConstInt(Int64Ty, InstHdl.getNextPC()), NewESPPtr);

        // sync GMRVals into stack.
        SyncAllGMRValue();

        GenIndirectJmp(Target);
        if (IsExitPC(InstHdl.getPC())) {
            ExitBB->eraseFromParent();
        }
    }
}

void X86Translator::translate_ret(GuestInst *Inst) {
    X86InstHandler InstHdl(Inst);

    // load return address from stack
    Value *OldESP = LoadGMRValue(Int64Ty, X86Config::RSP);
    Value *OldESPPtr = Builder.CreateIntToPtr(OldESP, Int64PtrTy);
    Value *RA = Builder.CreateLoad(Int64Ty, OldESPPtr);

    // adjust esp
    Value *NewESP = Builder.CreateAdd(OldESP, ConstInt(Int64Ty, 8));
    StoreGMRValue(NewESP, X86Config::RSP);

    // sync GMRVals into stack.
    SyncAllGMRValue();
    // Value *Target = call helper_lookup_tb_ptr

    GenIndirectJmp(RA);
    if (IsExitPC(InstHdl.getPC())) {
        ExitBB->eraseFromParent();
    }
}
