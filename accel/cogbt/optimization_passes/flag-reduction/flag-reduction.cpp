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

        IR_WITHOUT_TY(x86setja, __CF | __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjae, __CF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjb, __CF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjbe, __CF | __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setje, __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjne, __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjg, __ZF | __SF | __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjge, __SF | __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjl, __SF | __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjle, __ZF | __SF | __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjs, __SF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjns, __SF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjo, __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjno, __OF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjp, __PF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setjnp, __PF, __NONE, __NONE)

        IR_WITHOUT_TY(x86setloope, __ZF, __NONE, __NONE)
        IR_WITHOUT_TY(x86setloopne, __ZF, __NONE, __NONE)

        IR_WITHOUT_TY(x86mfflag, __ALL_FLAGS, __NONE, __NONE)
        IR_WITHOUT_TY(x86mtflag, __NONE, __ALL_FLAGS, __NONE)
    };

/* #define COGBT_PROFILE */

#ifdef COGBT_PROFILE
    static uint64_t NumberRemoveInstr = 0;
    static uint64_t NumberTotalInstr = 0;
#endif

    class TranslationInst {
        public:
            /// Constructor
            /// GenFlagBits == -1 representates this instruction does not define 
            /// the flag (only use), so this instruction should not be removed.
            TranslationInst(Instruction *Instr, uint8_t FlagBits = __INSTR_REMOVE): 
                Instr(Instr), GenFlagBits(FlagBits) {
                    const CallInst *CI = dyn_cast<CallInst>(Instr);
                    const Value *Operand = CI->getCalledOperand();
                    InstrName = Operand->getName().data();
#ifdef COGBT_PROFILE
                    NumberTotalInstr++;
#endif
                }

            const Instruction *getInstr() const { return Instr; }
            uint8_t getFlagBits() { return GenFlagBits; }

            TranslationInst &operator=(uint32_t FlagBits) {
                GenFlagBits = FlagBits;
                return *this;
            }

            /// const instruction warehouse iterator
            using const_instwh_iterator = 
                const std::map<std::string, FLAG_USEDEF>::iterator;

            /// The Flag bits this instruction use/def. 
            uint8_t getUse() {
                const_instwh_iterator it = INSTR_USEDEF.find(InstrName);
                assert(it != INSTR_USEDEF.end() && 
                        "inst is not in instruction warehouse.");
                return it->second.use;
            }
            uint8_t getDef() {
                const_instwh_iterator it = INSTR_USEDEF.find(InstrName);
                assert(it != INSTR_USEDEF.end() && 
                        "inst is not in instruction warehouse.");
                return it->second.def;
            }

            /// Remove unnecessary instructions according to the TranslationInst's GenFlagBits
            bool RemoveInstruction() {
                if (GenFlagBits == 0) {
                    /* dbgs() << "remove instruction: " << InstrName << "\n"; */
#ifdef COGBT_PROFILE
                    NumberRemoveInstr++;
#endif
                    Instr->eraseFromParent();
                    return true;
                }
                return false;
            }

            void dump(raw_ostream &OS) const {
                std::string BitsName = "";
                if (GenFlagBits == __INSTR_REMOVE) {
                    BitsName = "-1";
                } else {
                    if (GenFlagBits & __CF) BitsName += "CF ";
                    if (GenFlagBits & __PF) BitsName += "PF ";
                    if (GenFlagBits & __AF) BitsName += "AF ";
                    if (GenFlagBits & __ZF) BitsName += "ZF ";
                    if (GenFlagBits & __SF) BitsName += "SF ";
                    if (GenFlagBits & __OF) BitsName += "OF ";
                }
                OS << InstrName << "(" << (int)GenFlagBits << ")" << " : " << BitsName << "\n";
            }

        private:
            Instruction *Instr;
            std::string InstrName;
            /// The Flag Bits that this Instruction should generate.
            /// This instruction can be remove if GenFlagBits == 0.(default value is __INSTR_REMOVE)
            uint8_t GenFlagBits;
    };

    class TranslationBlock {
        public:
            friend class TranslationUnit;
            /// Constructor
            TranslationBlock(BasicBlock *BB) : 
                BB(BB), LiveIn(0), LiveOut(0), LiveUse(0), LiveDef(0) {
                    for (auto &Instr : BB->getInstList()) {
                        // Only add instruction related with FLAG register into Instrs.
                        if (!strcmp("call", Instr.getOpcodeName())) {
                            const CallInst *CI = dyn_cast<CallInst>(&Instr);
                            const Value *Operand = CI->getCalledOperand();
                            if (Operand->hasName() && 
                                    Operand->getName().startswith("llvm.loongarch") &&
                                    Operand->getName() != "llvm.loongarch.cogbtexit") {
                                TranslationInst *TI = new TranslationInst(&Instr);
                                Instrs.push_back(TI);

                                LiveDef |= TI->getDef();
                                LiveUse |= (TI->getUse() & ~LiveDef);
                            }
                        }
                    }
                }

            /// add Instruction into Instrs 
            void addInstr(TranslationInst *Instr) {
                Instrs.push_back(Instr);
            }

            /// Backward analysis to calculate Flag Bits that need to be 
            /// generated for each instruction
            void GenInstrFlagBits() {
                /* assert(!Instrs.empty() && "instruction list is empty."); */
                // The Flag Bits required by current instruction and subsequent instructions
                uint32_t standby_flag = LiveOut;
                std::vector<TranslationInst *>::reverse_iterator Iter = Instrs.rbegin();
                for (;Iter != Instrs.rend(); Iter++) {
                    TranslationInst *TI = *Iter; 
                    uint32_t def = TI->getDef();
                    uint32_t use = TI->getUse();
                    if (def)
                        *TI = def & standby_flag;
                    standby_flag = (standby_flag & ~def) | use;
                }
            }

            /// Record the TB's succssors
            void addNextBB(uint32_t idx) {
                assert(NextBBs.size() <= 2 && "BasicBlock has more than two succssors.");
                NextBBs.push_back(idx);
            }

            bool RemoveInstruction() {
                bool modify = false;
                for (auto &Instr : Instrs) {
                    modify |= Instr->RemoveInstruction();
                }
                return modify;
            }

            void dump(raw_ostream &OS) const {
                OS << BB->getName() << ": \n";
                for (auto &TI : Instrs) {
                    TI->dump(OS);
                }
                OS << "NextBB index: ";
                for (size_t i = 0; i < NextBBs.size(); i++)
                    OS << NextBBs.at(i) << ' ';
                OS << '\n';
            }

        private:
            BasicBlock *BB;
            std::vector<TranslationInst *> Instrs;
            std::vector<uint32_t> NextBBs;
            /// Tracking liveness of physical FLAG registers
            uint32_t LiveIn;
            uint32_t LiveOut;
            uint32_t LiveUse;
            uint32_t LiveDef;
    };

    class TranslationUnit {
        public:
            /// Constructor
            void initTranslationUnit(Function *Func) {
                this->Func = Func;
                TBList.clear();
                TBMap.erase(TBMap.begin(), TBMap.end());

                int i = 0;
                for (auto &Block : Func->getBasicBlockList()) {
                    TranslationBlock *TB = new TranslationBlock(&Block);
                    TBList.push_back(TB);
                    TBMap.insert(std::make_pair(&Block, i));
                    i++;
                }

                for (auto &Block : Func->getBasicBlockList()) {
                    std::map<BasicBlock *, uint32_t>::iterator OriBBIter = TBMap.find(&Block);
                    assert(OriBBIter != TBMap.end() && "cannot find block in TBMap.");
                    TranslationBlock *OriBB = TBList[OriBBIter->second];

                    succ_iterator SI = succ_begin(&Block), SE = succ_end(&Block);
                    // init the TranslationBlock's LiveIn and LiveOut
                    if (SI == SE) {     // without succssor
                        OriBB->LiveOut = __ALL_FLAGS;
                    } else {            // with succssor
                        OriBB->LiveOut = 0;
                        for (; SI != SE; ++SI) {
                            // store NextBB index into TranslationBlock.NextBBs
                            std::map<BasicBlock *, uint32_t>::iterator MapIter = TBMap.find(*SI);
                            assert(MapIter != TBMap.end() && "cannot find block in TBMap.");
                            OriBB->addNextBB(MapIter->second);
                        }
                    }
                }
            }

            ~TranslationUnit() {
                Func = NULL;
                TBList.clear();
                std::vector<TranslationBlock *>().swap(TBList);
                TBMap.clear();
            }

            /// add TranslationBlock into TBList
            void addTB(TranslationBlock *TB) {
                TBList.push_back(TB);
            }

            /// Compute liveness of each BasicBlock
            /// BB.LiveOut = U block(s).LiveIn, 's' is the succssor of BB
            /// BB.LiveIn  = (BB.LiveOut - BB.LiveDef) U BB.liveUse
            void ComputeLiveness() {
                std::vector<TranslationBlock *>::reverse_iterator Iter = TBList.rbegin();
                uint32_t OldLiveOut, OldLiveIn;
                bool endFlag = false;
                while (!endFlag) {
                    endFlag = true;
                    for(; Iter != TBList.rend(); Iter++) {
                        TranslationBlock *TB = *Iter;
                        OldLiveOut = TB->LiveOut;
                        OldLiveIn = TB->LiveIn;

                        TB->LiveOut |= getSuccssorLiveIn(TB);
                        TB->LiveIn = (TB->LiveOut & ~TB->LiveDef) | TB->LiveUse;

                        if (TB->LiveIn != OldLiveIn || TB->LiveOut != OldLiveOut)
                            endFlag = false;
                    }
                }
            }

            void GenInstrFlagBits() {
                for (auto &TB : TBList) {
                    TB->GenInstrFlagBits();
                }
            }

            bool RemoveInstruction() {
                bool modify = false;
                for (auto &TB : TBList) {
                    modify |= TB->RemoveInstruction();
                }
                return modify;
            }

            void dump(raw_ostream &OS) const {
                OS << "============== " << Func->getName() << " ==============\n";
                for (size_t i = 0; i < TBList.size(); i++) {
                    OS << "========== TranslationBlock " << i << " ==========\n";
                    TBList[i]->dump(OS);
                }
            }

        private:
            Function *Func;
            std::vector<TranslationBlock *> TBList;
            // The map is used to record BasicBlock* and its location in TBList
            std::map<BasicBlock *, uint32_t> TBMap;

            uint32_t getSuccssorLiveIn(TranslationBlock *TB) {
                uint32_t ret = 0;
                for (auto &idx : TB->NextBBs) {
                    TranslationBlock *OriBB = TBList[idx];
                    ret |= OriBB->LiveIn;
                }
                return ret;
            }
    };


    struct FlagReductionPass : public FunctionPass {
        static char ID;
        TranslationUnit TU;
        FlagReductionPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            TU.initTranslationUnit(&F);
            TU.ComputeLiveness();
            TU.GenInstrFlagBits();
            /* TU.dump(dbgs()); */

            bool ret = TU.RemoveInstruction();
            return ret;
        }

        void print(raw_ostream &OS, const Module *M) const override {
            TU.dump(OS);
        }

        /// This pass will not modify control-flow or teminator instructions.
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesCFG();
        } 

        bool doFinalization(Module &M) override { 
#ifdef COGBT_PROFILE
            dbgs() << "Total number of instructions related FLAG regiter: " 
                << NumberTotalInstr << "\n";
            dbgs() << "Remove the number of instructions: " 
                << NumberRemoveInstr << "\n";
#endif
            return false; 
        }


    };
}; // end namespace

// llvm uses ID's address to identify a pass, so initialization value is not important.
char FlagReductionPass::ID = 0;

// register Pass
// opt -load xx.so -@flag-reduction
static RegisterPass<FlagReductionPass> X("flag-reduction", "Flag Reduction Pass",
        false /* Only looks at CFG */,
        false /* Analysis Pass */);

FunctionPass *createFlagReductionPass() {
    return new FlagReductionPass();
}
