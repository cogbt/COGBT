#include "llvm/Pass.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "cogbt-x86-flag.h"
#include <vector>
#include <iostream>
#include <map>

using namespace llvm;

namespace {
    static std::map<std::string, FLAG_USEDEF> INSTR_USEDEF = {
        IR_WITH_BHWD(x86adc,  __CF, __ALL_FLAGS, __NONE)
        IR_WITH_BHWD(x86add,  __NONE, __ALL_FLAGS, __NONE)
        IR_WITH_WDU(x86add, __NONE, __ALL_FLAGS, __NONE)
        IR_WITH_BHWD(x86inc,     __NONE, __OF | __SZAPF, __NONE)
        IR_WITH_BHWD(x86sbc,     __CF, __ALL_FLAGS, __NONE)
        IR_WITH_BHWD(x86sub,     __NONE, __ALL_FLAGS, __NONE)
        IR_WITH_WDU(x86sub,     __NONE, __ALL_FLAGS, __NONE)
        IR_WITH_BHWD(x86dec,     __NONE, __OF | __SZAPF, __NONE)
        IR_WITH_BHWD(x86and,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86or,      __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86xor,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86mul,     __NONE, __ALL_FLAGS, __SZAPF)
        IR_WITH_BHWDU(x86mul,     __NONE, __ALL_FLAGS, __SZAPF)

        IR_WITH_BHWD(x86rcl,     __CF, __CF | __OF, __NONE)
        IR_WITH_BHWD(x86rcli,     __CF, __CF | __OF, __NONE)
        IR_WITH_BHWD(x86rcr,     __CF, __CF | __OF, __NONE)
        IR_WITH_BHWD(x86rcri,     __CF, __CF | __OF, __NONE)
        IR_WITH_BHWD(x86rotl,     __CF, __OF | __CF, __NONE)
        IR_WITH_BHWD(x86rotli,     __CF, __OF | __CF, __NONE)
        IR_WITH_BHWD(x86rotr,     __CF, __OF | __CF, __NONE)
        IR_WITH_BHWD(x86rotri,     __CF, __OF | __CF, __NONE)
        IR_WITH_BHWD(x86sll,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86slli,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86srl,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86srli,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86sra,     __NONE, __ALL_FLAGS, __AF)
        IR_WITH_BHWD(x86srai,     __NONE, __ALL_FLAGS, __AF)

        /* IR_WITHOUT_TY(x86setja, __CF | __ZF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjae, __CF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjb, __CF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjbe, __CF | __ZF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setje, __ZF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjne, __ZF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjg, __ZF | __SF | __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjge, __SF | __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjl, __SF | __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjle, __ZF | __SF | __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjs, __SF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjns, __SF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjo, __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjno, __OF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjp, __PF, __NONE, __NONE) */
        /* IR_WITHOUT_TY(x86setjnp, __PF, __NONE, __NONE) */

        IR_WITHOUT_TY(x86setloope, __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setloopne, __ZF, __NONE, __NONE)

        IR_WITHOUT_TY(x86mfflag, __ALL_FLAGS, __NONE, __NONE)
        IR_WITHOUT_TY(x86mtflag, __NONE, __ALL_FLAGS, __NONE)
    };


    enum X86SETType {
        JA  = 0,
        JAE ,
        JB  ,
        JBE ,
        JE  ,
        JNE ,
        JG  ,
        JGE ,
        JL  ,
        JLE ,
        JS  ,
        JNS ,
        JO  ,
        JNO ,
        JP  ,
        JNP ,
    };

    static std::pair<std::string, FLAG_USEDEF> X86SETJ[] = {
        [JA ] = IR_WITHOUT_TY(x86setja, __CF | __ZF, __NONE, __NONE)
        [JAE] = IR_WITHOUT_TY(x86setjae, __CF, __NONE, __NONE)
        [JB ] = IR_WITHOUT_TY(x86setjb, __CF, __NONE, __NONE)
        [JBE] = IR_WITHOUT_TY(x86setjbe, __CF | __ZF, __NONE, __NONE)
        [JE ] = IR_WITHOUT_TY(x86setje, __ZF, __NONE, __NONE)
        [JNE] = IR_WITHOUT_TY(x86setjne, __ZF, __NONE, __NONE)
        [JG ] = IR_WITHOUT_TY(x86setjg, __ZF | __SF | __OF, __NONE, __NONE)
        [JGE] = IR_WITHOUT_TY(x86setjge, __SF | __OF, __NONE, __NONE)
        [JL ] = IR_WITHOUT_TY(x86setjl, __SF | __OF, __NONE, __NONE)
        [JLE] = IR_WITHOUT_TY(x86setjle, __ZF | __SF | __OF, __NONE, __NONE)
        [JS ] = IR_WITHOUT_TY(x86setjs, __SF, __NONE, __NONE)
        [JNS] = IR_WITHOUT_TY(x86setjns, __SF, __NONE, __NONE)
        [JO ] = IR_WITHOUT_TY(x86setjo, __OF, __NONE, __NONE)
        [JNO] = IR_WITHOUT_TY(x86setjno, __OF, __NONE, __NONE)
        [JP ] = IR_WITHOUT_TY(x86setjp, __PF, __NONE, __NONE)
        [JNP] = IR_WITHOUT_TY(x86setjnp, __PF, __NONE, __NONE)
    };

#define COGBT_PROFILE

#ifdef COGBT_PROFILE
    static uint64_t NumberTESTJCC = 0;
    static uint64_t NumberCMPJCC = 0;
#endif

    struct PatternReductionPass : public FunctionPass {
        /// const instruction warehouse iterator
        using const_instwh_iterator = 
            const std::map<std::string, FLAG_USEDEF>::iterator;

        /// Get the index of Name in the warehouse, return -1 if not find.
        inline int getIndexWareHouse(std::string Name) {
            const_instwh_iterator it = INSTR_USEDEF.find(Name);
            if (it == INSTR_USEDEF.end())
                return -1;
            return std::distance(INSTR_USEDEF.begin(), it);
        }
        int getIndexSetj(std::string Name) {
            for (size_t i = 0; i < sizeof(X86SETJ) / sizeof(X86SETJ[0]); i++) {
                if (Name == X86SETJ[i].first)
                    return i;
            }
            return -1;
        }

        // This buff is used to collect lbt instructions' index in INSTR_USEDEF.
        // These instructions may affect the x86setjxx instruction's result. 
        // For simplicity, only one item is maintained.
#define FLAG_BUFF_SIZE (1)
#define FLGA_BUFF_LAST (FLAG_BUFF_SIZE - 1)

        int patternFlagBuff[FLAG_BUFF_SIZE] = {-1};
        CallInst* patternFlagIns[FLAG_BUFF_SIZE] = {nullptr};

        void collectFlagsBuff(CallInst* CI) {
            int index = getIndexWareHouse(CI->getCalledValue()->getName());
            assert(index != -1 && "collect failed");
            // insert into the end of buff
            for (int i = FLAG_BUFF_SIZE - 1; i > 0; i--) {
                patternFlagBuff[i - 1] = patternFlagBuff[i];
                patternFlagIns[i - 1] = patternFlagIns[i];
            }
            patternFlagBuff[FLAG_BUFF_SIZE - 1] = index;
            patternFlagIns[FLAG_BUFF_SIZE - 1] = CI;
        }

        inline void clearFlagsBuff() {
            for (int i = 0; i < FLAG_BUFF_SIZE; i++) {
                patternFlagBuff[i] = -1;
                patternFlagIns[i] = nullptr;
            }
        }

        bool isAndSameRegOperand(Value** Src) {
            int index = patternFlagBuff[FLGA_BUFF_LAST];

            // Pattern collection does not finish.
            if (index == -1) {
                /* assert(0 && "Pattern collection does not finish."); */
                return false;
            }

            auto it = INSTR_USEDEF.begin();
            std::advance(it, index);
            if (it->first.find("and.d") == std::string::npos)
                return false;

            CallInst* AndInst = patternFlagIns[FLGA_BUFF_LAST];
            if (AndInst->getOperand(0) != AndInst->getOperand(1)) 
                return false;

            assert(Src != nullptr);
            *Src = AndInst->getOperand(0);
            AndInst->dump();

            return true;
        }

        bool isSubRegOperand(Value** Src0, Value **Src1) {
            int index = patternFlagBuff[FLGA_BUFF_LAST];

            // Pattern collection does not finish.
            if (index == -1) {
                /* assert(0 && "Pattern collection does not finish."); */
                return false;
            }

            auto it = INSTR_USEDEF.begin();
            std::advance(it, index);
            if (it->first.find("sub.d") == std::string::npos)
                return false;

            CallInst* SubInst = patternFlagIns[FLGA_BUFF_LAST];

            /* auto* reg0 = dyn_cast<ConstantInt>(SubInst->getOperand(0)); */
            /* auto* reg1 = dyn_cast<ConstantInt>(SubInst->getOperand(1)); */
            /* if (reg0 || reg1) */
            /*     return false; */

            SubInst->dump();

            assert(Src0 != nullptr);
            *Src0 = SubInst->getOperand(0);
            assert(Src1 != nullptr);
            *Src1 = SubInst->getOperand(1);

            return true;
        }

        enum PatternMode {
            TEST_JCC ,
            CMP_JCC  ,
        };


        bool modifyIcmp(ICmpInst* Icmp, Value *Src0, Value *Src1, int x86setindex, 
                int mode) {
            int ret = false;
            if (Icmp->getPredicate() != ICmpInst::ICMP_EQ) {
                Icmp->dump();
                /* assert(0); */
                return false; 
            }

            if (mode == TEST_JCC) {
                Icmp->dump();
                switch (x86setindex) {
                    case JA  :
                    case JAE :
                    case JB  :
                    case JBE :
                        /* return false; */
                        assert(0);
                    case JE  :
                        Icmp->setPredicate(ICmpInst::ICMP_NE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JNE :
                        Icmp->setPredicate(ICmpInst::ICMP_EQ);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JG  :
                        Icmp->setPredicate(ICmpInst::ICMP_SLE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JGE :
                        Icmp->setPredicate(ICmpInst::ICMP_SLT);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JL  :
                        Icmp->setPredicate(ICmpInst::ICMP_SGE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JLE :
                        Icmp->setPredicate(ICmpInst::ICMP_SGT);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JS  :
                        Icmp->setPredicate(ICmpInst::ICMP_SGE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JNS :
                        Icmp->setPredicate(ICmpInst::ICMP_SLT);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, ConstantInt::get(Int64Ty, 0));
                        break;
                    case JO  :
                    case JNO :
                    case JP  :
                    case JNP :
                        /* return false; */
                        assert(0);
                        break;
                    default:
                        assert(0);
                }
#ifdef COGBT_PROFILE
                NumberTESTJCC++;
#endif
                ret |= true;
                dbgs() << "modify: ========== ";
                Icmp->dump();
            }

            if (mode == CMP_JCC) {
                Icmp->dump();
                switch (x86setindex) {
                    case JA  :
                        Icmp->setPredicate(ICmpInst::ICMP_ULE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JAE :
                        Icmp->setPredicate(ICmpInst::ICMP_ULT);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JB  :
                        Icmp->setPredicate(ICmpInst::ICMP_UGE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JBE :
                        Icmp->setPredicate(ICmpInst::ICMP_ULT);
                        Icmp->setOperand(1, Src0);
                        Icmp->setOperand(0, Src1);
                        break;
                    case JE  :
                        Icmp->setPredicate(ICmpInst::ICMP_NE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JNE :
                        Icmp->setPredicate(ICmpInst::ICMP_EQ);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JG  :
                        Icmp->setPredicate(ICmpInst::ICMP_SLE);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JGE :
                        Icmp->setPredicate(ICmpInst::ICMP_SLT);
                        Icmp->setOperand(0, Src0);
                        Icmp->setOperand(1, Src1);
                        break;
                    case JL  :
                        Icmp->setPredicate(ICmpInst::ICMP_SLE);
                        Icmp->setOperand(1, Src0);
                        Icmp->setOperand(0, Src1);
                        break;
                    case JLE :
                        Icmp->setPredicate(ICmpInst::ICMP_SLT);
                        Icmp->setOperand(1, Src0);
                        Icmp->setOperand(0, Src1);
                        break;
                    case JS  :
                    case JNS :
                    case JO  :
                    case JNO :
                    case JP  :
                    case JNP :
                        return false;
                    default:
                        assert(0);
                }
#ifdef COGBT_PROFILE
                NumberCMPJCC++;
#endif
                ret |= true;
                dbgs() << "modify: ========== ";
                Icmp->dump();

            }

            return ret;
        }


        bool handlePattern(CallInst *CI) {
            std::string InstName = CI->getCalledValue()->getName();
            bool ret = false;

            // x86setjxx
            if (InstName.find("x86setj") != std::string::npos) {
                int x86setindex = getIndexSetj(InstName);
                assert(x86setindex != -1 && "x86setj not find.");

                // test-jcc
                // The two operands of x86and instruction must be the same register.
                Value *Src0 = nullptr;
                Value *Src1 = nullptr;
                if (isAndSameRegOperand(&Src0)) {
                    assert(Src0 != nullptr);

                    if (CI->hasOneUse()) {
                        auto U = *CI->user_begin();
                        ICmpInst *icmp = dyn_cast<ICmpInst>(U);
                        if (!icmp)
                            goto give_up;
                        auto *imm = dyn_cast<ConstantInt>(icmp->getOperand(1));
                        if (!imm || imm->getValue() != 0)
                            goto give_up;
                        // modify icmp instruction
                        CI->dump();
                        if (modifyIcmp(icmp, Src0, Src1, x86setindex, TEST_JCC)) {
                            ret = true;
                            RemoveIns.push_back(CI);
                            /* CI->eraseFromParent(); */
                        }
                    }
                }

                // cmp-jcc
                if (isSubRegOperand(&Src0, &Src1)) {
                    assert(Src0 != nullptr);
                    assert(Src1 != nullptr);

                    if (CI->hasOneUse()) {
                        auto U = *CI->user_begin();
                        ICmpInst *icmp = dyn_cast<ICmpInst>(U);
                        if (!icmp)
                            goto give_up;
                        auto *imm = dyn_cast<ConstantInt>(icmp->getOperand(1));
                        if (!imm || imm->getValue() != 0)
                            goto give_up;
                        // modify icmp instruction
                        CI->dump();
                        if (modifyIcmp(icmp, Src0, Src1, x86setindex, CMP_JCC)) {
                            ret = true;
                            RemoveIns.push_back(CI);
                            /* CI->eraseFromParent(); */
                        }
                    }
                }

            }

give_up:
            return ret;
        }


        std::vector<Instruction *> RemoveIns;
        Module* Mod = nullptr;
        Type* Int64Ty = nullptr;

        static char ID;

        PatternReductionPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            Mod = F.getParent();
            Int64Ty = Type::getInt64Ty(Mod->getContext());
            RemoveIns.clear();

            int ret = false;

            for (auto &BB: F) {
                clearFlagsBuff();
                for (auto &Instr: BB) {
                    CallInst *CI = dyn_cast<CallInst>(&Instr);
                    if (!CI)
                        continue;
                    Value *Operand = CI->getCalledValue();
                    if (Operand->hasName() && 
                            Operand->getName().startswith("llvm.loongarch")) {
                        if (Operand->getName().find("cogbtexit") != std::string::npos) 
                            continue;

                        if (Operand->getName().find("x86setj") != std::string::npos || 
                                Operand->getName().find("x86mfflag") != std::string::npos) {
                            // read flag instruction
                            handlePattern(CI);
                        } else {
                            // write flag instruction
                            collectFlagsBuff(CI);
                        }
                    }
                }
            }

            for (size_t i = 0; i < RemoveIns.size(); i++) {
                /* RemoveIns[i]->dump(); */
                RemoveIns[i]->eraseFromParent();
                ret |= true;
            }

            return ret;
        }

        void print(raw_ostream &OS, const Module *M) const override {
            /* TU.dump(OS); */
        }

        /// This pass will not modify control-flow or teminator instructions.
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            /* AU.setPreservesCFG(); */
        } 

        bool doFinalization(Module &M) override { 
#ifdef COGBT_PROFILE
            dbgs() << "Remove number of instructions related pattern test-jcc: " 
                << NumberTESTJCC << "\n";
            dbgs() << "Remove number of instructions related pattern cmp-jcc: " 
                << NumberCMPJCC << "\n";
#endif
            return false; 
        }


    };
}; // end namespace

// llvm uses ID's address to identify a pass, so initialization value is not important.
char PatternReductionPass::ID = 0;

// register Pass
// opt -load xx.so -@flag-reduction
static RegisterPass<PatternReductionPass> X("pattern-reduction", "Pattern Reduction Pass",
        false /* Only looks at CFG */,
        false /* Analysis Pass */);

FunctionPass *createPatternReductionPass() {
    return new PatternReductionPass();
}
