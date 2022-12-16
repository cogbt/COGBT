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

// capsthone handler, will be used in some cs API.
static csh handle;
static vector<TranslationUnit *> TUs;

static bool guest_inst_is_cfi(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_RET);
}

static bool guest_inst_is_terminator(cs_insn *insn) {
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_RET) ||
           cs_insn_group(handle, insn, CS_GRP_INT);
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
    uint64_t EntryPoint, ExitPoint;
    std::set<JsonBlock> Blocks;
public:
    JsonFunc(std::string Name, uint64_t EntryPoint, uint64_t ExitPoint = 0)
        : Name(Name), EntryPoint(EntryPoint), ExitPoint(ExitPoint) {
        Blocks.clear();
    }

    uint64_t getEntryPoint() { return EntryPoint; }
    uint64_t getExitPoint() { return ExitPoint; }
    void setEntryPoint(uint64_t EntryPoint) { this->EntryPoint = EntryPoint; }
    void setExitPoint(uint64_t ExitPoint) { this->ExitPoint = ExitPoint; }

    void addJsonBlock(const JsonBlock &JB) { Blocks.insert(JB); }

    using Iterator = std::set<JsonBlock>::iterator;
    Iterator begin() { return Blocks.begin(); }
    Iterator end() { return Blocks.end(); }

    void dump() {
        fprintf(stderr, "Json Func :\n");
        fprintf(stderr, "  Name: %s\n", Name.c_str());
        fprintf(stderr, "  Entry: 0x%lx\n", EntryPoint);
        fprintf(stderr, "  Exit: 0x%lx\n", ExitPoint);
        fprintf(stderr, "  Blocks:\n");
        for (auto JB : Blocks) {
            fprintf(stderr, "    [0x%lx, 0x%lx)\n", JB.getEntry(),
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

static void GenJsonFunc(JsonFunc &JF, std::vector<std::string> &Blocks) {
    std::set<uint64_t> Visited, Unvisited;
    std::deque<uint64_t> WorkList;
    for (auto &s : Blocks) {
        uint64_t Entry = stol(s, nullptr, 16);
        WorkList.push_back(Entry);
        Unvisited.insert(Entry);
    }

    // If json doesn't contain function exit point, Find it here.
    if (JF.getExitPoint() == 0) {
        uint64_t Exit = *Unvisited.rbegin();
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            int res = cs_disasm(handle, (uint8_t *)Exit, 15, Exit, 1, &pins);
            assert(res && "cs_disasm error");
            Exit = pins->address + pins->size;
        } while (!guest_inst_is_cfi(pins));
        JF.setExitPoint(Exit);
    }

    // Calculate instruction boundary bitmap.
    BitMap BM(JF.getExitPoint() - JF.getEntryPoint());
    while (!WorkList.empty()) {
        uint64_t Entry = WorkList.front();
        WorkList.pop_front();
        Unvisited.erase(Entry);
        if (Visited.count(Entry))
            continue;
        Visited.insert(Entry);
        uint64_t pc = Entry;
        // disassemble to find a terminator.
        cs_insn *pins = nullptr;
        do {
            if (pins)
                cs_free(pins, 1);
            BM.set(pc - JF.getEntryPoint());
            int res = cs_disasm(handle, (uint8_t *)pc, 15, pc, 1, &pins);
            assert(res && "cs_disasm error");
            pc = pins->address + pins->size;

            // Strictly speaking, call and ret are not the termination
            // instructions of the basic block, but in order to be
            // consistent with qemu, we also divide these two instructions
            // into the terminator of the basic block
            if (cs_insn_group(handle, pins, CS_GRP_CALL) ||
                cs_insn_group(handle, pins, CS_GRP_INT)) {
                if (!Unvisited.count(pc)) {
                    WorkList.push_back(pc);
                    Unvisited.insert(pc);
                }
            }
        } while (!guest_inst_is_terminator(pins));
        if (pins)
            cs_free(pins, 1);
        /* JF.addJsonBlock(JsonBlock(entry, pc)); */
    }

    // Split overlapping basic blocks.
    assert(Unvisited.empty() && WorkList.empty());
    for (auto it = Visited.begin(); it != Visited.end(); ) {
        uint64_t Entry = *it;
        uint64_t NextEntry = *++it;
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
        } while (!guest_inst_is_terminator(pins) && Exit != NextEntry);
        if (pins)
            cs_free(pins, 1);
        JF.addJsonBlock(JsonBlock(Entry, Exit, InsNum));
    }
}

static void GenTU(JsonFunc &JF, TranslationUnit *TU) {
    for (auto it = JF.begin(); it != JF.end(); ++it) {
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
        tu_init(TU);
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
        JsonFunc JF(Name, stol(EntryPoint, nullptr, 16));
        GenJsonFunc(JF, Blocks);

        // generate TU
        TranslationUnit *TU = new TranslationUnit();
        GenTU(JF, TU);
        TUs.push_back(TU);
    }

}

void aot_gen(const char *pf) {
    LLVMTranslator *Translator = create_llvm_translator(0, 0);
    llvm_initialize(Translator);
    for (TranslationUnit *TU : TUs) {
        llvm_set_tu(Translator, TU);
        llvm_translate(Translator);
    }
    llvm_compile(Translator, true);
}

/* bool guest_inst_is_terminator(cs_insn *insn) { */
/*     return cs_insn_group(handle, insn, CS_GRP_JUMP) || */
/*            cs_insn_group(handle, insn, CS_GRP_RET) || */
/*            cs_insn_group(handle, insn, CS_GRP_CALL) || */
/*            cs_insn_group(handle, insn, CS_GRP_INT); */
/* } */

