#include "llvm/Pass.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include <vector>
#include <map>

using namespace llvm;

namespace {

#define COGBT_PROFILE

#ifdef COGBT_PROFILE
    static uint64_t NumberTotal = 0;
#endif

    struct SextReductionPass : public FunctionPass {
        static char ID;
        SextReductionPass() : FunctionPass(ID) {}

        /// This pass combine things like: 
        ///     %1 = trunc i64 %0 to i32
        ///     %2 = sext i32 %1 to i64
        ///     call void @llvm.loongarch.x86xxx.w(i64 %2, ...)
        /// into:
        ///     call void @llvm.loongarch.x86xxx.w(i64 %0, ...)
        bool SextCombine(Instruction& Instr) {
            bool flag = false;
            /* Instr.dump(); */

            char prefix = Instr.getOperand(2)->getName().back();
            if (prefix == 'u') {
                auto Iterator = Instr.getOperand(2)->getName().end();
                Iterator--;
                Iterator--;
                prefix = *Iterator;
            }
            unsigned int bitwidth = 0;
            switch(prefix) {
                case 'b':
                    bitwidth = 8;
                    break;
                case 'h':
                    bitwidth = 16;
                    break;
                case 'w':
                    bitwidth = 32;
                    break;
                case 'd':
                    return false;
                default:
                    assert(0 && "prefix is not in (b, h, w, d)");
            }

            for (int i = 0; i < 2; i++) {
                if (!isa<Constant>(Instr.getOperand(i))) {
                    // handle sext, zext instruction
                    auto *SExt = dyn_cast<SExtInst>(Instr.getOperand(i));
                    /* auto *ZExt = dyn_cast<ZExtInst>(Instr.getOperand(i)); */
                    if (!SExt)
                        continue;
                    /* if (ZExt) { */
                    /*     Instr.dump(); */
                    /*     assert(0 && "debug zext"); */
                    /* } */
                    if (SExt->getDestTy()->getIntegerBitWidth() != 64)
                        continue;
                    if (SExt->getSrcTy()->getIntegerBitWidth() != bitwidth)
                        continue;
                    /* SExt->dump(); */

                    // handle trunc instruction
                    auto *Trunc = dyn_cast<TruncInst>(SExt->getOperand(0));
                    if (!Trunc)
                        continue;
                    if (Trunc->getSrcTy()->getIntegerBitWidth() != 64)
                        continue;
                    if (Trunc->getDestTy()->getIntegerBitWidth() != bitwidth)
                        continue;
                    /* Trunc->dump(); */

                    // value replace
                    Instr.setOperand(i, Trunc->getOperand(0));
                    flag |= true;
                }
            }
#ifdef COGBT_PROFILE 
            NumberTotal++;
#endif
            return flag;
        }

        bool runOnFunction(Function &F) override {
            bool ret = false;

            if (F.hasFnAttribute("cogbt")) {
                for (auto &Block: F) {
                    for (auto &Instr: Block) {
                        if (Instr.getOpcode() != Instruction::Call) 
                            continue;
                        if (Instr.getNumOperands() != 3)
                            continue;
                        if (Instr.getOperand(2)->getName().find("x86")
                                == (size_t) -1)
                            continue;
                        if (Instr.getOperand(2)->getName().find("x86mtflag")
                                != (size_t) -1)
                            continue;
                        /* dbgs() << Instr.getOperand(2)->getName() << "\n"; */
                        ret |= SextCombine(Instr);
                    }
                }
            }

            return ret;
        }

        void print(raw_ostream &OS, const Module *M) const override {
            /* TU.dump(OS); */
        }

        /// This pass will not modify control-flow or teminator instructions.
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesCFG();
        } 

        bool doFinalization(Module &M) override { 
#ifdef COGBT_PROFILE
            dbgs() << "Total number of instructions replaced: " 
                << NumberTotal << "\n";
#endif
            return false; 
        }

    };
}; // end namespace

// llvm uses ID's address to identify a pass, so initialization value is not important.
char SextReductionPass::ID = 0;

// register Pass
// opt -load xx.so -@flag-reduction
static RegisterPass<SextReductionPass> X("sext-reduction", "Sext Reduction Pass",
        false /* Only looks at CFG */,
        false /* Analysis Pass */);

FunctionPass *createSextReductionPass() {
    return new SextReductionPass();
}
