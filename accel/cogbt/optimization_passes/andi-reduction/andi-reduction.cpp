#include "llvm/Pass.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/Constants.h"
#include <iostream>
#include <vector>
#include <map>

using namespace llvm;

namespace {

/* #define COGBT_PROFILE */

    struct AndiReductionPass : public FunctionPass {
        static char ID;
        AndiReductionPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            bool ret = false;

            if (F.hasFnAttribute("cogbt")) {
                for (auto &Block: F) {
                    for (auto &Instr: Block) {
                        if (Instr.getOpcode() != Instruction::And) 
                            continue;

                        auto *Call = dyn_cast<CallInst>(Instr.getOperand(0));
                        if (!Call || Call->getNumOperands() != 1 ||
                                Call->getOperand(0)->getName().find("x86setj")
                                == (size_t) -1)
                            continue;

                        auto *imm = dyn_cast<ConstantInt>(Instr.getOperand(1));
                        if (!imm || imm->getValue() != 1)
                            continue;

                        Instr.replaceAllUsesWith(Call);
                        /* Instr.eraseFromParent(); */
                        ret |= true;

                        /* Instr.dump(); */
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
            return false; 
        }

    };
}; // end namespace

// llvm uses ID's address to identify a pass, so initialization value is not important.
char AndiReductionPass::ID = 0;

// register Pass
// opt -load xx.so -@flag-reduction
static RegisterPass<AndiReductionPass> X("andi-reduction", "andi Reduction Pass",
        false /* Only looks at CFG */,
        false /* Analysis Pass */);

FunctionPass *createAndiReductionPass() {
    return new AndiReductionPass();
}
