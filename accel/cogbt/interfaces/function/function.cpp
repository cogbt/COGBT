#include "qemu/osdep.h"
#include "function.h"
#include "json-handle.h"
#include "capstone.h"
#include "translation-unit.h"
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <iostream>
#include <deque>
#include <algorithm>
#include <sstream>
#include <memory>

// capsthone handler, will be used in some cs API.
static csh handle;
static vector<TranslationUnit *> TUs;

static bool func_tu_inst_is_cfi(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET);
}

bool func_tu_inst_is_terminator(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           cs_insn_group(handle, insn, CS_GRP_INT);
}

bool func_tu_inst_is_funcexit(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_INT) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           (cs_insn_group(handle, insn, CS_GRP_JUMP) &&
            insn->detail->x86.operands[0].type != X86_OP_IMM);
}

void cogbt_function_init(void) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    TUs.clear();
}

void JsonFunc::formalize(uint64_t Boundary) {
    assert(Blocks.empty());
    for (auto it = BlockStrs.begin(); it != BlockStrs.end(); ) {
        uint64_t Entry = *it;
        uint64_t NextEntry = ++it != BlockStrs.end() ? *it :
            std::min(ExitPoint, Boundary);
        uint64_t Exit = Entry;
        uint64_t InsNum = 0;
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
            assert(res && "cs_disasm error");
            ++InsNum;
            Exit = pins->address + pins->size;
        } while (!func_tu_inst_is_terminator(pins) && Exit < NextEntry);
        if (pins)
            cs_free(pins, 1);
        Blocks.insert(JsonBlock(Entry, Exit, InsNum));
    }
}

static void GenTU(JsonFunc &JF, TranslationUnit *TU) {
    tu_init(TU);
    for (auto it = JF.begin(); it != JF.end(); ++it) {
        uint64_t Entry = it->getEntry();
        uint64_t InsNum = it->getInsNum();
        /* fprintf(stderr, "InsNum is %ld\n", InsNum); //debug */
        cs_insn **insns = (cs_insn **)calloc(InsNum, sizeof(cs_insn *));

        for (int i = 0; i < (int)InsNum; i++) {
            int res = cs_disasm(handle, (const uint8_t *)Entry, 15, Entry, 1,
                                insns + i);
            if (res == 0) {
                printf("Error! Disassemble inst at 0x%lx failed\n", Entry);
                exit(-1);
            }
            Entry = insns[i]->address + insns[i]->size;
        }
        assert(Entry == it->getExit());
        GuestBlock *block = guest_tu_create_block(TU);
        for (int i = 0; i < (int)InsNum; i++) {
            guest_block_add_inst(block, insns[i]);
        }
    }
}

// partition_helper - Partition Function.
// There are two scenarios that need to repartition.
//
// - Instructions that are considered as function ExitPoint are
//   as follows: call, syscall, jmp %rax、ret.
// - One Func's guest physical address range can overlap at most two pages.
static void partition_helper(JsonFunc &func, vector<JsonFunc> &NewFuncs) {
#define X86_PAGE_BITS   12
#define X86_PAGE_SIZE   (1 << X86_PAGE_BITS)
#define X86_PAGE_MASK   ((int64_t)-1 << X86_PAGE_BITS)
    uint64_t pc = func.getEntryPoint();
    uint64_t FuncBoundary = func.getExitPoint();
    // two pages boundary that current function can reach
    uint64_t pageBoundary = (pc & X86_PAGE_MASK) + X86_PAGE_SIZE * 2;
    // functions in partitionFuncs need to be partition again
    vector<int> partitionFuncs;
    // direct jmp target address
    set<uint64_t> targets;

    // 1. Partition by exit instrcutions
    func.getBlockStrs().clear();
    func.addBlockStrs(pc);
    cs_insn *pins = nullptr;
    do {
        if (pins)
            cs_free(pins, 1);
        int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
        assert(res && "cs_disasm error");
        pc = pins->address + pins->size;

        // add blockEntry
        if (func_tu_inst_is_terminator(pins) &&
                !func_tu_inst_is_funcexit(pins)) {
           func.addBlockStrs(pc);
        }
        // add target address
        if (cs_insn_group(handle, pins, CS_GRP_JUMP) &&
            pins->detail->x86.operands[0].type == X86_OP_IMM) {
            targets.insert(pins->detail->x86.operands[0].imm);
        }
    } while (!func_tu_inst_is_funcexit(pins) && pc < FuncBoundary);

    func.setExitPoint(pc);
    if (pc > pageBoundary) {
        // current func is numbered -1 in partitionFuncs
        partitionFuncs.push_back(-1);
    }

    // Partition - Construct new Function
    while (pc < FuncBoundary) {
        std::stringstream ss;
        ss << std::hex << pc;
        std::string Name("0x" + ss.str());
        uint64_t FuncEntry = pc;
        pageBoundary = (pc & X86_PAGE_MASK) + X86_PAGE_SIZE * 2;

        set<uint64_t> Blocks;
        Blocks.insert(FuncEntry);

        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
            assert(res && "cs_disasm error");
            pc = pins->address + pins->size;

            // add blockEntry
            if (func_tu_inst_is_terminator(pins) &&
                    !func_tu_inst_is_funcexit(pins)) {
                Blocks.insert(pc);
            }
            // add target address
            if (cs_insn_group(handle, pins, CS_GRP_JUMP) &&
                pins->detail->x86.operands[0].type == X86_OP_IMM) {
                targets.insert(pins->detail->x86.operands[0].imm);
            }
        } while (!func_tu_inst_is_funcexit(pins) && pc < FuncBoundary);

        NewFuncs.emplace_back(Name, FuncEntry, Blocks);
        NewFuncs.back().setExitPoint(pc);
        if (pc > pageBoundary) {
            partitionFuncs.push_back(NewFuncs.size());
        }
    }

    // add jmp target into funcs blockStrs
    for (set<uint64_t>::iterator sit = targets.begin(); sit != targets.end();) {
        while (sit != targets.end() && *sit < func.getEntryPoint()) {
            sit++;
        }
        while (sit != targets.end() && *sit < func.getExitPoint()) {
            if (func.getBlockStrs().count(*sit) == 0) {
                /* fprintf(stderr, "0x%lx in func 0x%lx\n", */
                /*         *sit, func.getEntryPoint()); */
                func.getBlockStrs().insert(*sit);
            }
            sit++;
        }
        for (int i = 0; i < (int) NewFuncs.size(); i++) {
            while (sit != targets.end() && *sit < NewFuncs[i].getExitPoint()) {
                if (NewFuncs[i].getBlockStrs().count(*sit) == 0) {
                    /* fprintf(stderr, "0x%lx in func 0x%lx\n", */
                    /*         *sit, NewFuncs[i].getEntryPoint()); */
                    NewFuncs[i].getBlockStrs().insert(*sit);

                }
                sit++;
            }
        }
        break;
    }

    // 2. Partition by GPA range
    while (!partitionFuncs.empty()) {
        // pop the last from the container
        int position = partitionFuncs.back();
        JsonFunc *JF = (position == -1) ? &func : &NewFuncs[position - 1];
        partitionFuncs.pop_back();
#ifdef CONFIG_COGBT_DEBUG
        /* JF->dump(stdout); */
        fprintf(stderr, "TranslationUnit: 0x%lx cross page.\n", JF->getEntryPoint());
#endif
        pc = JF->getEntryPoint();
        pageBoundary = (pc & X86_PAGE_MASK) + X86_PAGE_SIZE * 2;
        uint64_t exitPoint = JF->getExitPoint();
        assert(exitPoint > pageBoundary);

        assert(JF->getBlockStrs().size() > 0);
        auto it = JF->name_begin();
        auto et = JF->name_end();
        uint64_t blockEntry = 0;
        do {
            blockEntry = *it;
            if (blockEntry > pageBoundary) {
                // the last block GPA range overlap two pages, so it--.
                it--;
                break;
            } else if (blockEntry == pageBoundary) {
                break;
            } else {
                it++;
            }
        } while (it != et);
        blockEntry = *it;
        JF->setExitPoint(blockEntry);

        // Partition - Construct new Function
        /* auto erase_it = it; */
        uint64_t erase_pc = *it;
        while (it != et) {
            std::stringstream ss;
            ss << std::hex << blockEntry;
            std::string Name("0x" + ss.str());
            uint64_t FuncEntry = blockEntry;
            uint64_t FuncExit = exitPoint;
            set<uint64_t> Blocks;
            Blocks.insert(blockEntry);

            pc = blockEntry;
            pageBoundary = (pc & X86_PAGE_MASK) + X86_PAGE_SIZE * 2;
            it++;

            while (it != et) {
                blockEntry = *it;
                if (blockEntry < pageBoundary) {
                    Blocks.insert(blockEntry);
                    it++;
                } else if (blockEntry == pageBoundary) {    // next Function
                    FuncExit = blockEntry;
                    break;
                } else {
                    // the last block GPA range overlap two pages, so it--.
                    it--;
                    blockEntry = *it;
                    FuncExit = blockEntry;
                    Blocks.erase(std::next(Blocks.rbegin()).base());
                    break;
                }
            }

            if (it == et && exitPoint > pageBoundary) {
                // the last block GPA range overlap two pages, so it--.
                it--;
                blockEntry = *it;
                FuncExit = blockEntry;
                Blocks.erase(std::next(Blocks.rbegin()).base());
            }

            NewFuncs.emplace_back(Name, FuncEntry, Blocks);
            NewFuncs.back().setExitPoint(FuncExit);
        }
        JF = (position == -1) ? &func : &NewFuncs[position - 1];
        assert(JF->getBlockStrs().find(erase_pc) != JF->name_end());
        JF->name_erase(JF->getBlockStrs().find(erase_pc), JF->name_end());
    }
}

static void partition_funcs(vector<JsonFunc> &JsonFuncs) {
    vector<JsonFunc> Funcs;
    for(int i = 0; i < (int)JsonFuncs.size(); i++) {
        vector<JsonFunc> NewFuncs;
        // Calculate the Function ExitPoint
        uint64_t FuncBoundary = -1;
        if (i+1 < (int)JsonFuncs.size())
            FuncBoundary = JsonFuncs[i+1].getEntryPoint();
        uint64_t Exit = *JsonFuncs[i].name_rbegin();
        /* assert(Exit <= FuncBoundary); */
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
            assert(res && "cs_disasm error");
            Exit = pins->address + pins->size;
        } while (!func_tu_inst_is_cfi(pins) && Exit < FuncBoundary);
        JsonFuncs[i].setExitPoint(Exit);

        // Repartition function.
        partition_helper(JsonFuncs[i], NewFuncs);
        Funcs.insert(Funcs.end(), NewFuncs.begin(), NewFuncs.end());
    }
    JsonFuncs.insert(JsonFuncs.end(), Funcs.begin(), Funcs.end());
}

// block_parse - Parse path file.
static void block_parse(const char *pf, vector<JsonFunc> &JsonFuncs) {
#define MAX_INSN 200
    FILE *path = fopen(pf, "r");
    // The file is not exist
    if (path == nullptr)
        return;

    uint64_t pc;
    while (fscanf(path, "%lx", &pc) != EOF) {
        std::stringstream ss;
        ss << std::hex << pc;
        std::string Name("0x" + ss.str());
        uint64_t FuncEntry = pc;
        set<uint64_t> BlockStrs;
        BlockStrs.insert(pc);

        cs_insn *pins = nullptr;
        uint64_t InsNum = 0;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
            assert(res && "cs_disasm error");
            ++InsNum;
            pc = pins->address + pins->size;
        } while(!func_tu_inst_is_terminator(pins) && InsNum < MAX_INSN);

        JsonFuncs.emplace_back(Name, FuncEntry, BlockStrs);
        JsonFuncs.back().setExitPoint(pc);
        JsonFuncs.back().addJsonBlock(JsonBlock(FuncEntry, pc, InsNum));
    }
    fclose(path);
#undef MAX_INSN
}

void func_tu_parse(const char *pf) {
    // 1. Determine whether .json.txt file exists.
    //    Existence indicates that it is not the first execution.
    int func_txt_exist = false;
    char json_txt_path[255];
    strcpy(json_txt_path, pf);
    strcat(json_txt_path, ".json.txt");
    if (access(json_txt_path, F_OK) == 0) {
        func_txt_exist = true;
    }

    /* func_txt_exist = false; */
    // TODO: JsonFunc should use unique_ptr
    vector<JsonFunc> JsonFuncs;
    if (func_txt_exist) {
        // 2 parser .json.txt file
        json_parse(json_txt_path, JsonFuncs);
        std::sort(JsonFuncs.begin(), JsonFuncs.end());
    } else {
        // 2.1 parse .json file
        char json_path[255];
        strcpy(json_path, pf);
        strcat(json_path, ".json");
        json_parse(json_path, JsonFuncs);
        std::sort(JsonFuncs.begin(), JsonFuncs.end());
        // 2.2 Partition JsonFuncs
        partition_funcs(JsonFuncs);
        std::sort(JsonFuncs.begin(), JsonFuncs.end());
        // 2.3. Formalize JsonFunc: calculate Blocks in JsonFunc
        for (int i = 0; i < (int)JsonFuncs.size(); i++) {
            uint64_t FuncBoundary = JsonFuncs[i].getExitPoint();
            JsonFuncs[i].formalize(FuncBoundary);
        }
        // 2.4. Dump JsonFuncs
        strcat(json_path, ".txt");
        json_dump(json_path, JsonFuncs);
    }

    // 3. Determine whether .path file exists.
    char block_path[255];
    strcpy(block_path, pf);
    strcat(block_path, ".path");
    block_parse(block_path, JsonFuncs);
    std::sort(JsonFuncs.begin(), JsonFuncs.end());

    // 4. generate TU
    for (int i = 0; i < (int)JsonFuncs.size(); i++) {
        /* JsonFuncs[i].dump(stdout); */
        TranslationUnit *TU = new TranslationUnit();
        GenTU(JsonFuncs[i], TU);
        TUs.push_back(TU);
    }
}

void func_aot_gen(void) {
    LLVMTranslator *Translator = create_llvm_translator(0, 0);
    llvm_initialize(Translator);
    for (TranslationUnit *TU : TUs) {
        if (debug_guest_inst(Translator)) {
            fprintf(stderr, "+--------------------------------------------+\n");
            fprintf(stderr, "|               Guest Function               |\n");
            fprintf(stderr, "+--------------------------------------------+\n");
            for (auto bit = TU->begin(); bit != TU->end(); ++bit) {
                for (auto iit = bit->begin(); iit != bit->end(); ++iit) {
                    fprintf(stderr, "0x%lx  %s\t%s\n", (*iit)->address,
                            (*iit)->mnemonic, (*iit)->op_str);
                }
            }
        }
        llvm_set_tu(Translator, TU);
        llvm_translate(Translator);
        llvm_compile(Translator, true);
    }
    llvm_finalize(Translator);
}
