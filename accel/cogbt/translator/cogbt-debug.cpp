#include "cogbt-debug.h"
#include "llvm/MC/MCAsmInfo.h"

Disassembler::Disassembler(std::string &TripleName) {
    std::string Error;
    TheTarget = llvm::TargetRegistry::lookupTarget(TripleName, Error);
    if (!TheTarget) {
        dbgs() << Error;
    }

    Triple TheTriple(TripleName);

    std::unique_ptr<MCRegisterInfo> MRI(TheTarget->createMCRegInfo(TripleName));
    assert(MRI && "Unable to create MCRegInfo.\n");

    const MCTargetOptions MCOptions = llvm::mc::InitMCTargetOptionsFromFlags();
    std::unique_ptr<MCAsmInfo> MAI(
        TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
    assert(MAI && "Unable to create MCAsmInfo.\n");

    std::unique_ptr<MCInstrInfo> MII(TheTarget->createMCInstrInfo());
    assert(MII && "Unalbe to create MCInstrInfo.\n");

    MSTI.reset(TheTarget->createMCSubtargetInfo(TripleName, "", ""));
    assert(MSTI && "Unable to create MCSubTargetInfo.\n");

    MIA.reset(TheTarget->createMCInstrAnalysis(MII.get()));
    assert(MIA && "Unable to create MCInstrAnalysis.\n");

    MCContext MCCtx(TheTriple, MAI.get(), MRI.get(), MSTI.get());
    IP.reset(TheTarget->createMCInstPrinter(TheTriple, 0, *MAI, *MII, *MRI));
    IP->setPrintImmHex(true);

    MCD.reset(TheTarget->createMCDisassembler(*MSTI, MCCtx));
}

void Disassembler::PrintInst(uint64_t Addr, size_t Size, uint64_t PC) {
    uint64_t Len;
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(Addr), Size);

    for (uint64_t Idx = 0; Idx < Size; Idx += Len) {
        MCInst Inst;
        std::string Str;
        if (MCD->getInstruction(Inst, Len, Bytes.slice(Idx), Addr + Idx,
                                nulls())) {
            dbgs() << format("0x%08" PRIx64 ":", PC);

            /* DumpBytes(Bytes.slice(Start, Len), OS); */
            IP->printInst(&Inst, PC, "", *MSTI, dbgs());

            if (MIA && (MIA->isCall(Inst) || MIA->isUnconditionalBranch(Inst) ||
                MIA->isConditionalBranch(Inst))) {
                uint64_t Target;
                if (MIA->evaluateBranch(Inst, PC, Len, Target)) {
                    dbgs() << " <" << format("0x%08" PRIx64, Target) << ">";
                }
            }
        } else {
            dbgs() << "\t<internal disassembler error>";
            if (Len == 0)
                Len = 1;
        }

        dbgs() << "\n";
        PC += Len;
    }
}
