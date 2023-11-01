#ifndef COGBT_DEBUG_H
#define COGBT_DEBUG_H

#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/Target/TargetMachine.h"

#if (LLVM_VERSION_MAJOR > 8)
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/MC/TargetRegistry.h"
#else
#include "llvm/Support/TargetRegistry.h"
#endif

using namespace llvm;

//===---------------------------------------------------------------------====//
// Guest & Host machine code disassembler definition.
//===---------------------------------------------------------------------====//
class Disassembler {
    const Target *TheTarget;
    std::unique_ptr<MCDisassembler> MCD;   ///< Binary to MCInst Disassembler.
    std::unique_ptr<MCInstPrinter> IP;     ///< Print MCInst.

    std::unique_ptr<MCSubtargetInfo> MSTI; ///< MC subtarget info.
    std::unique_ptr<MCInstrAnalysis> MIA;  ///< MC instruction analyzer.
    std::unique_ptr<MCAsmInfo> MAI;        ///< MC assemble info.
    std::unique_ptr<MCInstrInfo> MII;      ///< MC instruction info.
    std::unique_ptr<MCContext> MCtx;       ///< MC Context
    std::unique_ptr<MCRegisterInfo> MRI;   ///< MCRegisterInfo

public:
    Disassembler(const std::string &TripleName);
    ~Disassembler() {}
    void PrintInst(uint64_t Addr, size_t Size, uint64_t PC);
};

//===---------------------------------------------------------------------====//
// COGBT debugger definition.
//===---------------------------------------------------------------------====//
class Debugger {
public:
  enum DebugMode {
      D_NONE      = 0ULL,
      D_GUEST_INS = 1ULL << 1,
      D_IR        = 1ULL << 2,
      D_IR_OPT    = 1ULL << 3,
      D_HOST_INS  = 1ULL << 4,
      D_CPU_STATE = 1ULL << 5,
      D_ALL       = D_GUEST_INS | D_IR | D_IR_OPT | D_HOST_INS,
  };

  /// Constructor - Parse env variable COGBT_DEBUG_MODE
  Debugger();

  /// DebugXXX - Check whether this debugger should debug some options.
  bool DebugGuestIns() {
      return Mode & D_GUEST_INS;
  }
  bool DebugIR() {
      return Mode & D_IR;
  }
  bool DebugIROpt() {
      return Mode & D_IR_OPT;
  }
  bool DebugHostIns() {
      return Mode & D_HOST_INS;
  }
  bool DebugCPUState() {
      return Mode & D_CPU_STATE;
  }
  bool DebugAll() {
      return Mode == D_ALL;
  }

private:
  DebugMode Mode;        /* The debug level */
};

#endif
