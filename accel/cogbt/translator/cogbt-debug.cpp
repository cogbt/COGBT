#include "cogbt-debug.h"
#include "llvm/MC/MCAsmInfo.h"

Disassembler::Disassembler(const std::string &TripleName) {
    std::string Error;
    TheTarget = llvm::TargetRegistry::lookupTarget(TripleName, Error);
    if (!TheTarget) {
        dbgs() << Error << "\n";
    }

    Triple TheTriple(TripleName);

    MRI.reset(TheTarget->createMCRegInfo(TripleName));
    assert(MRI && "Unable to create MCRegInfo.\n");

#if (LLVM_VERSION_MAJOR > 8)
    const MCTargetOptions MCOptions = llvm::mc::InitMCTargetOptionsFromFlags();
    MAI.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
#else
    MAI.reset(TheTarget->createMCAsmInfo(*MRI, TripleName));
#endif
    assert(MAI && "Unable to create MCAsmInfo.\n");

    MII.reset(TheTarget->createMCInstrInfo());
    assert(MII && "Unalbe to create MCInstrInfo.\n");

    MSTI.reset(TheTarget->createMCSubtargetInfo(TripleName, "", ""));
    assert(MSTI && "Unable to create MCSubTargetInfo.\n");

    MIA.reset(TheTarget->createMCInstrAnalysis(MII.get()));
    assert(MIA && "Unable to create MCInstrAnalysis.\n");

#if (LLVM_VERSION_MAJOR > 8)
    MCtx.reset(new MCContext(TheTriple, MAI.get(), MRI.get(), MSTI.get()));
#else
    MCtx.reset(new MCContext(MAI.get(), MRI.get(), nullptr));
#endif
    IP.reset(TheTarget->createMCInstPrinter(TheTriple, 0, *MAI, *MII, *MRI));
    IP->setPrintImmHex(true);

    MCD.reset(TheTarget->createMCDisassembler(*MSTI, *MCtx));
}

void Disassembler::PrintInst(uint64_t Addr, size_t Size, uint64_t PC) {
    uint64_t Len;
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(Addr), Size);

    for (uint64_t Idx = 0; Idx < Size; Idx += Len) {
        MCInst Inst;
        std::string Str;
#if (LLVM_VERSION_MAJOR > 8)
        if (MCD->getInstruction(Inst, Len, Bytes.slice(Idx), Addr + Idx,
                                nulls())) {
#else
        if (MCD->getInstruction(Inst, Len, Bytes.slice(Idx), Addr + Idx,
                                nulls(), nulls())) {
#endif
            dbgs() << format("0x%08" PRIx64 ":", PC);

            /* DumpBytes(Bytes.slice(Start, Len), OS); */
#if (LLVM_VERSION_MAJOR > 8)
            IP->printInst(&Inst, PC, "", *MSTI, dbgs());
#else
            IP->printInst(&Inst, dbgs(), "", *MSTI);
#endif

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

Debugger::Debugger() : Mode(D_NONE) {
    static std::map<std::string, DebugMode> EnvMap = {
        {"guest_ins", D_GUEST_INS},
        {"ir", D_IR},
        {"ir_opt", D_IR_OPT},
        {"host_ins", D_HOST_INS},
        {"cpu_state", D_CPU_STATE},
    };

    std::string EnvStr("");
    if (char *p = getenv("COGBT_DEBUG_MODE")) {
        EnvStr = p;
    }
    std::string EnvItem;
    for (char c : EnvStr) {
        if (c == ',') {
            // convert string to corresponding mode
            if (EnvMap.count(EnvItem)) {
                Mode = (DebugMode)(Mode | EnvMap[EnvItem]);
                EnvItem.clear();
            } else {
                dbgs() << "Unkown debug mode " << EnvItem << "\n";
                exit(-1);
            }
        }
        else EnvItem += c;
    }
    if (!EnvItem.empty()) {
        // convert string to corresponding mode
        if (EnvMap.count(EnvItem)) {
            Mode = (DebugMode)(Mode | EnvMap[EnvItem]);
            EnvItem.clear();
        } else {
            dbgs() << "Unkown debug mode " << EnvItem << "\n";
            exit(-1);
        }
    }
}
