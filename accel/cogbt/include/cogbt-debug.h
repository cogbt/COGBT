#ifndef COGBT_DEBUG_H
#define COGBT_DEBUG_H

#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/MC/TargetRegistry.h"

using namespace llvm;

class Disassembler {
    const Target *TheTarget;
    std::unique_ptr<MCDisassembler> MCD;   ///< Binary to MCInst Disassembler.
    std::unique_ptr<MCInstPrinter> IP;     ///< Print MCInst.

    std::unique_ptr<MCSubtargetInfo> MSTI; ///< MC subtarget info.
    std::unique_ptr<MCInstrAnalysis> MIA;  ///< MC instruction analyzer.
public:
    Disassembler(std::string &TripleName);
    void PrintInst(uint64_t Addr, size_t Size, uint64_t PC);
};

#endif
