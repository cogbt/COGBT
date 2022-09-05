#ifndef LLVM_TRANSLATOR_H
#define LLVM_TRANSLATOR_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;

class LLVMTranslator {
    LLVMContext Context;
    Module *Mod;
};

#endif
