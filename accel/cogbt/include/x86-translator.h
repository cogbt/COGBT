#ifndef X86_TRANSLATOR_H
#define X86_TRANSLATOR_H

#include "llvm-translator.h"
#include "x86-config.h"
#include "x86-inst-handler.h"
#include "x86-opnd-handler.h"

class X86Translator final : public LLVMTranslator, public X86Config {
public:
    X86Translator(uintptr_t CacheBegin, size_t CacheSize)
        : LLVMTranslator(CacheBegin, CacheSize, "loongarch64-pc-linux-gnu",
                         "loongarch64-pc-linux-gnu"),
          CurrInst(nullptr) {}

private: /// Currently translated instruction.
    GuestInst *CurrInst;

    /// InitializeFunction - Initialize the basic framework of the translation
    /// function, such as `entry` block(binding physical register to IR value),
    /// `exit` block(sync modified guest register state into physical register),
    ///
    /// This function implements the initialization of the X86 guest translation
    /// function.
    virtual void InitializeFunction(StringRef FuncName) override;

    virtual void DeclareExternalSymbols() override;

    virtual void GenPrologue() override;

    virtual void GenEpilogue() override;

    virtual void AddExternalSyms() override;

    virtual void TranslateInitialize() override;
    virtual void Translate() override;
    virtual void TranslateFinalize() override;

    /// @name X86 translate functions.
#define HANDLE_X86_INST(opcode, name) void translate_##name(GuestInst *);
#include "x86-inst.def"
#undef HANDLE_X86_INST

    /// ConstInt - Get a integer constant value.
    Value *ConstInt(Type *Ty, uint64_t Val) {
        return ConstantInt::get(Ty, Val);
    }

    /// GetOpndType - Get the llvm type of x86 operand.
    Type *GetOpndLLVMType(X86Operand *Opnd);
    Type *GetOpndLLVMType(int size);

    /// LoadGMRValue - Load the GMR value from GMRStates. If GMRVals have cached
    /// this value, return it directly. Otherwise load it from GMRStates first.
    /// NOTE! \p Ty should be integer type.
    Value *LoadGMRValue(Type *Ty, int GMRId, bool isHSubReg = false);

    /// StoreGMRValue - Store value V to GMRVals, Assuming that V won't touch
    /// other part of GMR[GMRId]
    void StoreGMRValue(Value *V, int GMRId, bool isHSubReg = false);

    /// CalcMemAddr - Generate llvm IRs to calculate memory address of a memory
    /// operand.
    Value *CalcMemAddr(X86Operand *Opnd);

    /// LoadOperand - Generate llvm IRs to load a x86 operand and return the
    /// loaded value.
    Value *LoadOperand(X86Operand *SrcOpnd, Type *LoadTy = nullptr);

    /// StoreOperand - Generate llvm IRs to store a value into a x86 operand.
    void StoreOperand(Value *val, X86Operand *DestOpnd);

    /// CalcEflag - Generate llvm IRs to define all eflags.
    void CalcEflag(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);

    /// GetLBTIntrinsic - Generate a LBT Intrinsic to calculate eflag.
    void GetLBTIntrinsic(StringRef Name, Value *Src0, Value *Src1);

    /// GenCF/OF - Generate llvm IRs to define CF/OF eflag.
    void GenCF(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);
    void GenOF(GuestInst *Inst, Value *Dest, Value *Src1, Value *Src2);

    /// FlushGMRValue - Flush GMR value into CPUX86State.
    /// ReloadGMRValue - Reload GMR value from CPUX86State.
    void FlushGMRValue(int GMRId);
    void ReloadGMRValue(int GMRId);

    /// SyncGMRValue - Sync GMR value into GMRStates.
    void SyncGMRValue(int GMRId);
    void SyncAllGMRValue();

    /// BindPhysicalReg - Bind latest guest register values to mapped host
    /// physical registers
    void BindPhysicalReg();

    /// FlushXMMT0 - In qemu, some simd helper use xmm_t0 and mmx_t0 as implicit
    /// source operand, so translator need to flush the source value into them
    /// and then call helpers.
    void FlushXMMT0(Value *XMMV, Type *FlushTy = nullptr);
    void FlushMMXT0(Value *MMXV, Type *FlushTy = nullptr);

    /// FlushFPRValue - Flush FPR(ST0 or FT0) value into CPUX86State.
    /// \p FPR is the name of the floating-point register, \p FV is the
    /// floating-point value to be saved, \p isInt indicates whether FV is
    /// regarded as an integer or a floating-point value
    void FlushFPRValue(std::string FPR, Value *FV, bool isInt);
    /// ReloadFPRValue - Reload FPR(FT0 or ST0) value from CPUX86State with \p
    /// LoadSize bytes.
    Value *ReloadFPRValue(std::string FPR, int LoadSize, bool isInt);

    /// CallFunc - Generate llvm IRs to call a llvm function, maybe a helper.
    Value *CallFunc(FunctionType *FuncTy, std::string Name,
                    ArrayRef<Value *> Args);

    /// SetLBTFlag - Move value \p FV into inner LBT Flag register.
    void SetLBTFlag(Value *FV, int mask = 0x3f);

    /// GetLBTFlag - Get inner LBT Flag register value.
    Value *GetLBTFlag(int mask = 0x3f);

    /// GenMMXSSEHelper - Gen a call to tcg helper, \p Inst should have 2
    /// operands, the first operand may be mmx/xmm/mm64/mm128, the second
    /// operand should be mmx or xmm.
    void GenMMXSSEHelper(std::string Name, GuestInst *Inst);

    ///@name X86Translator Helper functioins.

    /// GenJCCExit - Generate llvm IRs to do jcc exit.
    /// \p Inst is the x86 jcc instruction and \p Cond is the jump condition.
    void GenJCCExit(GuestInst *Inst, Value *Cond);

    /// FIXME: should be replace with firend class(Only to make the coding
    /// style more canonical)
    /// GenFPUHelper - Gen a call to tcg helper.
    void GenFPUHelper(GuestInst *Inst, std::string Name, int Flags);

    /// GenFCMOVHelper - Gen llvm irs to do fcmovcc by using lbt intrinsic \p
    /// LBTIntrinic.
    void GenFCMOVHelper(GuestInst *Inst, std::string LBTIntrinic);

    /// @name X87 FPU translator helper functions.


    Value * getFT0Ptr();

    ///   FP64CompareSW - f64 compares with f64 , result show in FPU State Words
    ///   Note: if LHS > RHS C3:C0 = 00 , LHS = RHS 10 , LHS < RHS 01
    ///   Usually ST0 is RHS
    void FP64CompareSW(Value *LHS, Value *RHS);

    ///   FP64CompareSW - f64 compares with f64  , result show in EFlag
    ///   Note: if LHS > RHS ZF:CF = 00 , LHS = RHS 10 , LHS < RHS 01
    ///   Usually ST0 is RHS
    ///   NEEDED TO FLASH GMR
    void FP64CompareEFLAG(Value *LHS, Value *RHS);

    /// getPrecisonCtrl - Get the PC value
    /// 00B float, 10B double, 11B double Ext
    Value *getPrecisonCtrl(void);

    Value *GetFpusPtr(void);

    Value *GetFpucPtr(void);

    /// StoreToFPR - Store value V into FPStack[fpi].
    void StoreToFPR(Value *V, Value *fpi);

    /// SetFPUTop - Adjust FPU stack top value to fpi.
    void SetFPUTop(Value *fpi);

    /// SetFPTag - set FPTag[fpi] to v.
    void SetFPTag(Value *fpi, uint8_t v);

    /// GetFPRPtr - Get the pointer of FPStack[fpi].
    Value *GetFPRPtr(Value *fpi, Type *FPRType);

    /// GetFPUTop - Get the current FPU stack top value.
    Value *GetFPUTop(void);

    /// LoadFromFPR - Load value from FPStack[fpi].
    Value *LoadFromFPR(Value *fpi, Type *FPRType);
};

#endif
