#include "qemu/osdep.h"
#include "function.h"
#include "capstone.h"
#include "translation-unit.h"
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string>
#include <iostream>
#include <set>
#include <deque>
#include <algorithm>
#include <sstream>

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
            insn->detail->x86.operands[0].type == X86_OP_REG);
}
//===---------------------------------------------------------------------====//
// JsonBlock is used to record basic block info in a json file.
//===---------------------------------------------------------------------====//
class JsonBlock {
    uint64_t Entry;  ///< Entry point of basic block.
    uint64_t Exit;   ///< Exit point of basic blcok.
    uint64_t InsNum; ///< Block instruction nums.
public:
    JsonBlock(uint64_t Entry, uint64_t Exit, uint64_t InsNum)
        : Entry(Entry), Exit(Exit), InsNum(InsNum) {}
    uint64_t getEntry() const { return Entry; }
    uint64_t getExit() const { return Exit; }
    uint64_t getInsNum() const { return InsNum; }

    bool operator<(const JsonBlock &JB) const {
        return Entry < JB.Entry || (Entry == JB.Entry && Exit < JB.Exit);
    }
};

//===---------------------------------------------------------------------====//
// JsonFunc is used to record function info in a json file.
//===---------------------------------------------------------------------====//
class JsonFunc {
    std::string Name;
    uint64_t EntryPoint, ExitPoint = 0;
    std::vector<std::string> BlockStrs;
    std::set<JsonBlock> Blocks;
public:
    JsonFunc(std::string Name, uint64_t EntryPoint,
             std::vector<std::string> &BS)
        : Name(Name), EntryPoint(EntryPoint), BlockStrs(std::move(BS)) {
        Blocks.clear();
    }

    uint64_t getEntryPoint() { return EntryPoint; }
    uint64_t getExitPoint() { return ExitPoint; }
    void setEntryPoint(uint64_t EntryPoint) { this->EntryPoint = EntryPoint; }
    void setExitPoint(uint64_t ExitPoint) { this->ExitPoint = ExitPoint; }
    /* void setBoundary(uint64_t Boundary) { this->Boundary = Boundary; } */

    void formalize(uint64_t Boundary);

    void addJsonBlock(const JsonBlock &JB) { Blocks.insert(JB); }

    using Iterator = std::set<JsonBlock>::iterator;
    Iterator begin() { return Blocks.begin(); }
    Iterator end() { return Blocks.end(); }

    using Name_Iterator = std::vector<std::string>::iterator;
    using Name_Reverse_Iterator = std::vector<std::string>::reverse_iterator;
    Name_Iterator name_begin() { return BlockStrs.begin(); }
    Name_Iterator name_end() { return BlockStrs.end(); }
    Name_Iterator name_erase(Name_Iterator it, Name_Iterator et) {
        return BlockStrs.erase(it, et);
    }
    Name_Reverse_Iterator name_rbegin() { return BlockStrs.rbegin(); }
    Name_Reverse_Iterator name_rend() { return BlockStrs.rend(); }

    bool operator<(const JsonFunc &JF) const {
        return EntryPoint < JF.EntryPoint;
    }

    void dump(FILE *ff) {
        fprintf(ff, "Json Func :\n");
        fprintf(ff, "  Name: %s\n", Name.c_str());
        fprintf(ff, "  Entry: 0x%lx\n", EntryPoint);
        fprintf(ff, "  Exit: 0x%lx\n", ExitPoint);
        fprintf(ff, "  Blocks:\n");
        for (auto JB : Blocks) {
            fprintf(ff, "    [0x%lx, 0x%lx)\n", JB.getEntry(),
                    JB.getExit());
        }
    }
};

//===---------------------------------------------------------------------====//
// BitMap is a simple bitmap implementation.
//===---------------------------------------------------------------------====//
class BitMap {
    std::vector<uint64_t> bm;
public:
    BitMap() = delete;
    BitMap(size_t NumElements) {
        bm.resize((NumElements + 63) >> 6, 0);
    }

    void set(unsigned idx) {
        assert(idx < (bm.size() << 6));
        bm[idx / 64] |= 1 << (idx % 64);
    }

    bool test(unsigned idx) {
        assert(idx < (bm.size() << 6));
        return (bm[idx / 64] >> (idx % 64)) & 1;
    }
};

void cogbt_function_init(void) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    TUs.clear();
}

static void parseFuncValue(const char *&scanner, std::string &Name,
                           std::string &EntryPoint,
                           std::vector<std::string> &Blocks) {
    assert(*scanner == '{');
    while (*scanner != '}') {
        ++scanner; // skip '{' or ','
        while (isspace(*scanner)) ++scanner; // skip space.
        std::string Key;
        while (!isspace(*scanner) && *scanner != ':') {
            Key += *scanner++;
        }

        while (isspace(*scanner)) ++scanner;
        assert(*scanner == ':');
        ++scanner;
        while (isspace(*scanner)) ++scanner;

        if (Key == "\"Name\"") {
            while (!isspace(*scanner) && *scanner != ',') {
                Name += *scanner++;
            }
            while (isspace(*scanner)) ++scanner;
        } else if (Key == "\"EntryPoint\"") {
            while (!isspace(*scanner) && *scanner != ',') {
                if (*scanner != '"')
                    EntryPoint += *scanner;
                ++scanner;
            }
            while (isspace(*scanner)) ++scanner;
        } else {
            assert(*scanner == '[' && "Blocks is not json array");
            ++scanner;
            std::string Block;
            while (true) {
                if (isspace(*scanner) || *scanner == ',' || *scanner == ']') {
                    if (!Block.empty()) {
                        Blocks.push_back(Block);
                        Block.clear();
                    }
                } else {
                    if (*scanner != '"')
                        Block += *scanner;
                }
                if (*scanner == ']')
                    break;
                else ++scanner;
            }
            ++scanner; // skip ']'
            while (isspace(*scanner)) ++scanner;
        }
    }

    ++scanner; //skip '}'
    while (isspace(*scanner)) ++scanner;
}

void JsonFunc::formalize(uint64_t Boundary) {
    std::set<uint64_t> Visited, Unvisited;
    std::deque<uint64_t> WorkList;
#if 0
    for (auto &s : BlockStrs) {
        uint64_t Entry = stol(s, nullptr, 16);
        WorkList.push_back(Entry);
        Unvisited.insert(Entry);
    }
    // If json doesn't contain function exit point, Find it here.
    if (ExitPoint == 0) {
        uint64_t Exit = *Unvisited.rbegin(); // last block in this function.
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
            assert(res && "cs_disasm error");
            Exit = pins->address + pins->size;
        } while (!func_tu_inst_is_cfi(pins) && Exit < Boundary);
        ExitPoint = Exit;
    }

    // Calculate instruction boundary bitmap.
    BitMap BM(ExitPoint - EntryPoint);
    while (!WorkList.empty()) {
        uint64_t Entry = WorkList.front();
        WorkList.pop_front();
        Unvisited.erase(Entry);
        if (Visited.count(Entry))
            continue;
        Visited.insert(Entry);
        // disassemble to find a terminator.
        uint64_t pc = Entry;
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            BM.set(pc - EntryPoint);
            int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
            assert(res && "cs_disasm error");
            pc = pins->address + pins->size;

            // Strictly speaking, call and int are not the termination
            // instructions of the basic block, but in order to be
            // consistent with qemu, we also divide these two instructions
            // into the terminator of the basic block
            if (cs_insn_group(handle, pins, CS_GRP_CALL) ||
                cs_insn_group(handle, pins, CS_GRP_INT)) {
              if (!Unvisited.count(pc) && !Visited.count(pc) &&
                  pc < ExitPoint) {
                WorkList.push_back(pc);
                Unvisited.insert(pc);
              }
            }
        } while (!func_tu_inst_is_terminator(pins) && pc < ExitPoint);
        if (pins)
            cs_free(pins, 1);
    }

    // Split overlapping basic blocks.
    assert(Unvisited.empty() && WorkList.empty());
#else
    for (auto &s : BlockStrs) {
        uint64_t Entry = stol(s, nullptr, 16);
        Visited.insert(Entry);
    }
#endif
    for (auto it = Visited.begin(); it != Visited.end(); ) {
        uint64_t Entry = *it;
        uint64_t NextEntry = ++it == Visited.end() ? ExitPoint : *it;
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
        /* addJsonBlock(JsonBlock(Entry, Exit, InsNum)); */
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

// parse all function entry and contained basic block entries.
void func_tu_json_parse(const char *pf) {
    // 1. mmap json file first.
    int fd = open(pf, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Open json file error!");
        exit(-1);
    };
    struct stat filestat;
    if (fstat(fd, &filestat) == -1) {
        fprintf(stderr, "Fstat json file error!");
        exit(-1);
    }
    size_t filesz = filestat.st_size;
    const char *json =
        (const char *)mmap(NULL, filesz, PROT_READ, MAP_PRIVATE, fd, 0);

    // 2. parse json
    std::vector<JsonFunc> JsonFuncs;
    const char *scanner = json, *eof = json + filesz;
    while (isspace(*scanner)) ++scanner;
    assert(*scanner == '{' && "json file doesn't start with {");
    while (scanner < eof && *scanner != '}') {
        ++scanner; // skip '{' or ','
        while (isspace(*scanner)) ++scanner;
        // scanner points to func key.
        std::string funcID;
        while (*scanner != ':' && !isspace(*scanner)) {
            funcID += *scanner++;
        }

        // skip ':'
        while (isspace(*scanner)) ++scanner;
        assert(*scanner == ':' && "Error function value");
        ++scanner;
        while (isspace(*scanner)) ++scanner;
        assert(*scanner == '{' &&
               "Eexpected function value should starts with {");

        // parse function value.
        std::string Name, EntryPoint;
        std::vector<std::string> Blocks;
        parseFuncValue(scanner, Name, EntryPoint, Blocks);

        // generate JsonFunc
        JsonFunc JF(Name, stol(EntryPoint, nullptr, 16), Blocks);
        JsonFuncs.push_back(std::move(JF));
    }

    std::sort(JsonFuncs.begin(), JsonFuncs.end());

    // 3. repartition function. Instructions that are considered as function
    // ExitPoint are as follows: call, syscall, jmp %rax、ret.
    std::vector<JsonFunc> NewFuns;
    for(int i = 0; i < (int)JsonFuncs.size(); i++) {
        uint64_t FuncBoundary = -1;
#if 0
        if (i+1 < (int)JsonFuncs.size())
            FuncBoundary = JsonFuncs[i+1].getEntryPoint();
        else {  // Calculate the last Function ExitPoint
            uint64_t Exit = stol(*JsonFuncs[i].name_rbegin(), nullptr, 16);
            cs_insn *pins = nullptr;
            do {
                if (pins)
                    cs_free(pins, 1);
                int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
                assert(res && "cs_disasm error");
                Exit = pins->address + pins->size;
            } while (!func_tu_inst_is_cfi(pins) && Exit < FuncBoundary);
            FuncBoundary = Exit;
        }
#else
        {  // Calculate the Function ExitPoint
            if (i+1 < (int)JsonFuncs.size())
                FuncBoundary = JsonFuncs[i+1].getEntryPoint();
            uint64_t Exit = stol(*JsonFuncs[i].name_rbegin(), nullptr, 16);
            cs_insn *pins = nullptr;
            do {
                if (pins)
                    cs_free(pins, 1);
                int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
                assert(res && "cs_disasm error");
                Exit = pins->address + pins->size;
            } while (!func_tu_inst_is_cfi(pins) && Exit < FuncBoundary);
            FuncBoundary = Exit;
        }
#endif

        uint64_t pc = JsonFuncs[i].getEntryPoint();
        auto it = JsonFuncs[i].name_begin();
        auto et = JsonFuncs[i].name_end();
        uint64_t blockEntry = stol(*it, nullptr, 16);
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
            assert(res && "cs_disasm error");
            while (pc >= blockEntry && it != et) {
                it++;
                if (it != et)
                    blockEntry = stol(*it, nullptr, 16);
            }
            pc = pins->address + pins->size;
        } while (!func_tu_inst_is_funcexit(pins) && pc < FuncBoundary);
        // Calculate function ExitPoint. if the loop exits due to
        // pc >= FuncBoundary, then pc is not accurate as ExitPoint.
        // An example:
        //      functionA:
        //          0x501:   jmp 851
        //          0x506:   nop
        //      functionB:
        //          0x50d:
        // In this case, functionA's ExitPoint is 0x506 rather than 0x50d.
        /* if (pc < FuncBoundary) */
            JsonFuncs[i].setExitPoint(pc);

        auto erase_it = it;
        while (pc < FuncBoundary) {    // need to partition
            std::stringstream ss;
            ss << std::hex << pc;
            std::string Name("\"0x" + ss.str() + "\"");
            uint64_t FuncEntry = pc;
            std::vector<std::string> Blocks;
            if (FuncEntry != blockEntry)
                Blocks.push_back(ss.str());
            do {
                if (pins)
                    cs_free(pins, 1);
                int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
                assert(res && "cs_disasm error");
                while (pc >= blockEntry && it != et) {
                    Blocks.push_back(std::move(*it));   // add to new Func
                    it++;
                    if (it != et)
                        blockEntry = stol(*it, nullptr, 16);
                }
                pc = pins->address + pins->size;
            } while (!func_tu_inst_is_funcexit(pins) && pc < FuncBoundary);

            JsonFunc JF(Name, FuncEntry, Blocks);
            /* if (pc < FuncBoundary) */
                JF.setExitPoint(pc);
            NewFuns.push_back(std::move(JF));
        }
        JsonFuncs[i].name_erase(erase_it, et);
    }
    JsonFuncs.insert(JsonFuncs.end(), NewFuns.begin(), NewFuns.end());
    std::sort(JsonFuncs.begin(), JsonFuncs.end());

#ifdef CONFIG_COGBT_DEBUG
    extern char* exec_path;
    FILE *ff = NULL;
    char func_file[1024] = {0};
    strcpy(func_file, exec_path);
    strcat(func_file, ".func.txt");
    if (!ff) {
        ff = fopen(func_file, "w+");
    }
#endif
    // 4. generate TU
    for (int i = 0; i < (int)JsonFuncs.size(); i++) {
        uint64_t FuncBoundary = -1;
        if (i+1 < (int)JsonFuncs.size())
            FuncBoundary = JsonFuncs[i+1].getEntryPoint();
        JsonFuncs[i].formalize(FuncBoundary);
#ifdef CONFIG_COGBT_DEBUG
        JsonFuncs[i].dump(ff);
#endif
        TranslationUnit *TU = new TranslationUnit();
        GenTU(JsonFuncs[i], TU);
        TUs.push_back(TU);
    }
#ifdef CONFIG_COGBT_DEBUG
    if (ff) {
        fflush(ff);
        fclose(ff);
    }
#endif
}

void aot_gen(const char *pf) {
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

/* bool func_tu_inst_is_terminator(cs_insn *insn) { */
/*     return cs_insn_group(handle, insn, CS_GRP_JUMP) || */
/*            cs_insn_group(handle, insn, CS_GRP_RET) || */
/*            cs_insn_group(handle, insn, CS_GRP_CALL) || */
/*            cs_insn_group(handle, insn, CS_GRP_INT); */
/* } */

