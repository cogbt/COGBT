#include "qemu/osdep.h"
#include "frontend.h"
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

using std::unique_ptr;
using std::shared_ptr;

// capsthone handler, will be used in some cs API.
static csh handle;
static vector<TranslationUnit *> TUs;

static bool func_tu_inst_is_cfi(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET);
}

static bool inst_is_conditional_jmp(cs_insn *insn) {
    if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
        switch (insn->id) {
            case X86_INS_JAE:
            case X86_INS_JA:
            case X86_INS_JBE:
            case X86_INS_JB:
            case X86_INS_JE:
            case X86_INS_JGE:
            case X86_INS_JG:
            case X86_INS_JLE:
            case X86_INS_JL:
            case X86_INS_JNE:
            case X86_INS_JNO:
            case X86_INS_JNP:
            case X86_INS_JNS:
            case X86_INS_JO:
            case X86_INS_JP:
            case X86_INS_JS:
            case X86_INS_JCXZ:
            case X86_INS_JECXZ:
            case X86_INS_JRCXZ:
                return true;
        }
    }
    return false;
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
        uint64_t NextEntry = ++it != BlockStrs.end() ? *it : Boundary;
            /* std::min(ExitPoint, Boundary); */
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
        /* } while (!func_tu_inst_is_terminator(pins)); */
        if (pins)
            cs_free(pins, 1);
        Blocks.insert(JsonBlock(Entry, Exit, InsNum));
    }
}

static void GenTU(shared_ptr<JsonFunc> JF, TranslationUnit *TU) {
    tu_init(TU);
    for (auto it = JF->begin(); it != JF->end(); ++it) {
        uint64_t Entry = it->getEntry();
        uint64_t InsNum = it->getInsNum();

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

// block_parse - Parse path file.
static void block_parse(const char *pf, vector<shared_ptr<JsonFunc>> &JsonFuncs) {
#define MAX_INSN 200
    FILE *path = fopen(pf, "r");
    // The file is not exist
    if (path == nullptr) {
        fprintf(stderr, "Path file is not existed.\n");
        return;
    }

    uint64_t pc;
    while (fscanf(path, "%lx", &pc) != EOF) {
#ifdef CONFIG_COGBT_DEBUG
        if (json_funcs_search(JsonFuncs, pc) != -1) {
            fprintf(stderr, "0x%lx has existed in JsonFuncs.\n", pc);
            continue;
        }
#endif

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

        shared_ptr<JsonFunc> JF(new JsonFunc(Name, FuncEntry, BlockStrs));
        JF->setExitPoint(pc);
        JF->setFuncBoundary(pc);
        JF->addJsonBlock(JsonBlock(FuncEntry, pc, InsNum));
        JsonFuncs.push_back(JF);
    }
    fclose(path);
#undef MAX_INSN
}

// partition_helper - Partition Function.
// There are two scenarios that need to repartition.
//
// - Instructions that are considered as function ExitPoint are
//   as follows: call, syscall, jmp %rax、ret.
// - One Func's guest physical address range can overlap at most two pages.
static void partition_helper(shared_ptr<JsonFunc> func,
        vector<shared_ptr<JsonFunc>> &NewFuncs) {
#define X86_PAGE_BITS   12
#define X86_PAGE_SIZE   (1 << X86_PAGE_BITS)
#define X86_PAGE_MASK   ((int64_t)-1 << X86_PAGE_BITS)
    uint64_t pc = func->getEntryPoint();
    uint64_t FuncBoundary = func->getFuncBoundary();
    // two pages boundary that current function can reach
    uint64_t pageBoundary = (pc & X86_PAGE_MASK) + X86_PAGE_SIZE * 2;
    // direct/conditional jmp target address
    std::deque<uint64_t> targets;

    // 1. Partition by exit instrcutions and GPA range
    func->getBlockStrs().clear();
    func->addBlockStrs(pc);

    cs_insn *pins = nullptr;
    do {
        if (pins)
            cs_free(pins, 1);
        int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
        assert(res && "cs_disasm error");
        pc = pins->address + pins->size;

        // over GPA range
        if (pc > pageBoundary) {
            uint64_t ExitPoint = *func->name_rbegin();
            func->getBlockStrs().erase(--func->name_end());
            func->setExitPoint(ExitPoint);
            /* func->setFuncBoundary(ExitPoint); */
            pc = ExitPoint;
#ifdef CONFIG_COGBT_DEBUG
            fprintf(stderr, "TranslationUnit: [0x%lx ~ 0x%lx) over pageBoundary(0x%lx). "
                "It will be fix to [0x%lx ~ 0x%lx). \n",
                func->getEntryPoint(), FuncBoundary, pageBoundary,
                func->getEntryPoint(), func->getExitPoint());
#endif
            // Note: Prevent `jmp/br target` in range [ExitPoint, pageBoundary)
            // from being inserted into func->BlockStrs. Because the ending of
            // these basic blocks must exceed the pageBoundary.
            pageBoundary = ExitPoint;
            break;
        }
        // meet function exit instruction
        if (func_tu_inst_is_funcexit(pins)) {
            // During a conditional jmp insert, pins->address may be inserted
            // into targets. We should remove it.
            if (!targets.empty() && targets.back() == pins->address) {
                targets.pop_back();
            }
            func->setExitPoint(pc);
            break;
        } else if (func_tu_inst_is_terminator(pins)) {
            if (pc >= FuncBoundary)
                break;
            // insert into BlockStrs
            func->addBlockStrs(pc);
        }
        // add target address
        if (cs_insn_group(handle, pins, CS_GRP_JUMP) &&
            pins->detail->x86.operands[0].type == X86_OP_IMM) {
            targets.push_back(pins->detail->x86.operands[0].imm);
            if (inst_is_conditional_jmp(pins)) {
                targets.push_back(pc);
            }
        }
    } while (pc < FuncBoundary);

    if (pc < FuncBoundary) {
        std::stringstream ss;
        ss << std::hex << pc;
        std::string Name("0x" + ss.str());
        shared_ptr<JsonFunc> JF(new JsonFunc(Name, pc, FuncBoundary));
        NewFuncs.push_back(JF);
    } else {
        func->setExitPoint(FuncBoundary);
    }

    // 2. insert jmp target into funcs blockStrs
    uint64_t Boundary = -1;
    if (FuncBoundary <= pageBoundary) {
        Boundary = FuncBoundary;
    } else {
        Boundary = pageBoundary;
        func->setFuncBoundary(pageBoundary);
    }

    set<uint64_t> Visited;
#define TARGETS_THRESHOLD 4096
    bool targets_handle = true;
    while (!targets.empty()) {
        uint64_t target = targets.front();
        targets.pop_front();
        Visited.insert(target);
        if (target < func->getEntryPoint())
            continue;
        if (target >= Boundary)
            continue;

        func->getBlockStrs().insert(target);

        uint64_t ExitPoint = func->getExitPoint();
        if (target >= ExitPoint) {
            uint64_t entry = target;
            cs_insn *pins = nullptr;
            do {
                if (pins)
                    cs_free(pins, 1);
                int res = cs_disasm(handle, (uint8_t *)entry, 15, entry, 1, &pins);
                assert(res && "cs_disasm error");
                entry = pins->address + pins->size;
                // add target address
                if (targets_handle && cs_insn_group(handle, pins, CS_GRP_JUMP) &&
                    pins->detail->x86.operands[0].type == X86_OP_IMM) {
                    if (Visited.count(pins->detail->x86.operands[0].imm) == 0) {
                        targets.push_back(pins->detail->x86.operands[0].imm);
                        if (targets.size() > TARGETS_THRESHOLD)
                            targets_handle = false;
                    }
                    if (targets_handle && inst_is_conditional_jmp(pins)) {
                        if (Visited.count(entry) == 0) {
                            targets.push_back(entry);
                            if (targets.size() > TARGETS_THRESHOLD)
                                targets_handle = false;
                        }
                    }
                }
            } while (!func_tu_inst_is_terminator(pins) && entry < Boundary);
        }
    }
#undef TARGETS_THRESHOLD
    /* func->dump(stderr); */
}

static void partition_funcs(vector<shared_ptr<JsonFunc>> &JsonFuncs) {
    std::deque<shared_ptr<JsonFunc>> WorkList;
    set<uint64_t> Visited;
    for(size_t i = 0; i < JsonFuncs.size(); i++) {
        WorkList.push_back(JsonFuncs[i]);
        Visited.insert(JsonFuncs[i]->getEntryPoint());
    }
    JsonFuncs.clear();

    while (!WorkList.empty()) {
        vector<shared_ptr<JsonFunc>> NewFuncs;

        shared_ptr<JsonFunc> JF = WorkList.front();
        WorkList.pop_front();
        partition_helper(JF, NewFuncs);
        // insert NewFuncs into WorkList
        for(size_t i = 0; i < NewFuncs.size(); i++) {
            if (Visited.count(NewFuncs[i]->getEntryPoint()) == 0) {
                WorkList.push_back(NewFuncs[i]);
                Visited.insert(NewFuncs[i]->getEntryPoint());
            }
        }
        // insert funcs partitioned into JsonFuncs
        JsonFuncs.push_back(JF);
    }
}

static void json_funcs_sort(vector<shared_ptr<JsonFunc>> &JsonFuncs) {
    std::sort(JsonFuncs.begin(), JsonFuncs.end(),
            [](const shared_ptr<JsonFunc>& x, const shared_ptr<JsonFunc>& y) {
            return x->getEntryPoint() < y->getEntryPoint();
        });
}

int json_funcs_search(vector<shared_ptr<JsonFunc>> &JsonFuncs, uint64_t target) {
    int right = JsonFuncs.size() - 1;
    int left = 0, middle = 0;

    while (left <= right) {
        middle = (left + right) / 2;
        if (JsonFuncs[middle]->getEntryPoint() < target)
            left = middle + 1;
        else if (JsonFuncs[middle]->getEntryPoint() > target)
            right = middle - 1;
        else
            return middle;
    }
    return -1;
}

// Calculate the Function ExitPoint
static void calculate_func_boundary(vector<shared_ptr<JsonFunc>> &JsonFuncs) {
    for(size_t i = 0; i < JsonFuncs.size(); i++) {
        if (JsonFuncs[i]->getFuncBoundary() != (uint64_t) -1)
            continue;
        uint64_t FuncBoundary = -1;
        if (i+1 < JsonFuncs.size())
            FuncBoundary = JsonFuncs[i+1]->getEntryPoint();
        uint64_t Exit = -1;
        if (JsonFuncs[i]->getBlockStrs().empty()) {     // elf parser
            Exit = JsonFuncs[i]->getEntryPoint();
        } else {    // json file parser
            Exit = *JsonFuncs[i]->name_rbegin();
        }
        assert(Exit <= FuncBoundary);
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
            assert(res && "cs_disasm error");
            Exit = pins->address + pins->size;
        } while (!func_tu_inst_is_cfi(pins) && Exit < FuncBoundary);
        JsonFuncs[i]->setFuncBoundary(Exit);
    }
}

#ifdef CONFIG_COGBT_DEBUG
static void check_json_funcs(vector<shared_ptr<JsonFunc>> &JsonFuncs,
        const char* message) {
    // 1. Function to check if there are duplicate addresses in vector.
    set<uint64_t> Visited;
    for (auto JF: JsonFuncs) {
        if (Visited.count(JF->getEntryPoint())) {
            fprintf(stderr, "%s: address = 0x%lx appears multiple times.\n",
                    message, JF->getEntryPoint());
            exit(-1);
        }
        Visited.insert(JF->getEntryPoint());
    }
}
#endif

static void first_parse(const char* exec_path, vector<shared_ptr<JsonFunc>> &JsonFuncs) {
    // 1. parse entries in .symtab which TYPE is FUNC
    parse_elf_format(exec_path, JsonFuncs);
    json_funcs_sort(JsonFuncs);
#ifdef CONFIG_COGBT_DEBUG
    check_json_funcs(JsonFuncs, "elf parse");
#endif

    // 2. parse .json file
    char json_path[255];
    strcpy(json_path, exec_path);
    strcat(json_path, ".json");
    json_parse(json_path, JsonFuncs, JSON_ORIGIN);
    json_funcs_sort(JsonFuncs);
#ifdef CONFIG_COGBT_DEBUG
    check_json_funcs(JsonFuncs, "json parse");
#endif

    // 3. Calculate the Function Boundary
    calculate_func_boundary(JsonFuncs);

    // 4. Partition JsonFuncs
    partition_funcs(JsonFuncs);
    json_funcs_sort(JsonFuncs);
#ifdef CONFIG_COGBT_DEBUG
    check_json_funcs(JsonFuncs, "partition funcs");
#endif

    // 5. parse .trace

    // 6. Formalize JsonFunc: calculate Blocks in JsonFunc
    for (size_t i = 0; i < JsonFuncs.size(); i++) {
        uint64_t FuncBoundary = JsonFuncs[i]->getFuncBoundary();
        JsonFuncs[i]->formalize(FuncBoundary);
    }

    // 7. Dump JsonFuncs
    strcat(json_path, ".txt");
    json_dump(json_path, JsonFuncs);
}

void func_tu_parse(const char *pf) {
    // Lookup whether .json.txt file exists.
    // Existence indicates that it is not the first execution.
    int func_txt_exist = false;
    char json_txt_path[255];
    strcpy(json_txt_path, pf);
    strcat(json_txt_path, ".json.txt");
    if (access(json_txt_path, F_OK) == 0) {
        func_txt_exist = true;
    }

    vector<shared_ptr<JsonFunc>> JsonFuncs;
    if (func_txt_exist) {
        // 2 parser .json.txt file
        json_parse(json_txt_path, JsonFuncs, JSON_FUNC_TXT);
        json_funcs_sort(JsonFuncs);
    } else {
        first_parse(pf, JsonFuncs);
    }

    // 3. Determine whether .path file exists.
    char block_path[255];
    strcpy(block_path, pf);
    strcat(block_path, ".path");
    block_parse(block_path, JsonFuncs);
    json_funcs_sort(JsonFuncs);

    // 4. generate TU
    for (size_t i = 0; i < JsonFuncs.size(); i++) {
        /* JsonFuncs[i]->dump(stdout); */
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
            TU->dump();
        }
        llvm_set_tu(Translator, TU);
        llvm_translate(Translator);
        llvm_compile(Translator, true);
        delete TU;
    }
    llvm_finalize(Translator);
}
