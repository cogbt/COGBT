#include "json-handle.h"
#include "json.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <iostream>
#include <fstream>
#include <map>

using std::map;
using json = nlohmann::json;

void json_parse(const char *pf, vector<JsonFunc> &JsonFuncs) {
    // 1. Check whether json file exists.
    if (access(pf, F_OK) != 0) {
        fprintf(stderr, "Open json file error!");
        exit(-1);
    }

    // 2. Parse function value.
    std::ifstream is(pf);
    json data;
    try {
        data = json::parse(is);
    } catch (json::exception &e) {
        std::cerr << e.what() << std::endl;
        exit(-1);
    }

    for (auto& func: data) {
        string Name;
        uint64_t EntryPoint, ExitPoint = -1;
        set<uint64_t> BlockStrs;
        set<JsonBlock> Blocks;

        assert(func["Name"].is_string());
        Name = func["Name"].get<string>();

        assert(func["EntryPoint"].is_string());
        EntryPoint = stol(func["EntryPoint"].get<string>(), nullptr, 16);

        if (!func["ExitPoint"].is_null()) {
            assert(func["ExitPoint"].is_string());
            ExitPoint = stol(func["ExitPoint"].get<string>(), nullptr, 16);
        }

        assert(func["Blocks"].is_array());
        for (auto &Block: func["Blocks"]) {
            if (Block.is_object()) {    // .json.txt file
                uint64_t Entry = 0, Exit = -1, InsNum = 0;

                assert(Block["Entry"].is_string());
                Entry = stol(Block["Entry"].get<string>(), nullptr, 16);

                assert(Block["Exit"].is_string());
                Exit = stol(Block["Exit"].get<string>(), nullptr, 16);

                assert(Block["InsNum"].is_string());
                InsNum = stol(Block["InsNum"].get<string>());

                BlockStrs.insert(Entry);
                Blocks.insert(JsonBlock(Entry, Exit, InsNum)); 
            } else if (Block.is_string()) {     // .json file
                BlockStrs.insert(stol(Block.get<string>(), nullptr, 16));
            } else {
                assert(0);
            }
        }

        // generate JsonFunc
        JsonFuncs.emplace_back(Name, EntryPoint, BlockStrs);
        JsonFuncs.back().setExitPoint(ExitPoint);
        if (!Blocks.empty())
            JsonFuncs.back().addJsonBlocks(Blocks);
    }
}

static string ltos(uint64_t num) {
    std::stringstream ss;
    ss << std::hex << num;
    return "0x" + ss.str();
}

void json_dump(const char *pf, vector<JsonFunc> &JsonFuncs) {
    json data;

    for (auto &JF: JsonFuncs) {
        json func;
        func["Name"] = JF.getName();
        func["EntryPoint"] = ltos(JF.getEntryPoint());
        func["ExitPoint"] = ltos(JF.getExitPoint());
        vector<map<string, string>> blocks;
        for (auto &Block: JF) {
            map<string, string> bm;
            bm["Entry"]  = ltos(Block.getEntry());
            bm["Exit"]   = ltos(Block.getExit());
            bm["InsNum"] = std::to_string(Block.getInsNum());
            blocks.push_back(bm);
        }
        func["Blocks"] = blocks;

        data[ltos(JF.getEntryPoint())] = func;
    }

    std::ofstream os(pf);
    os << std::setw(4) << data << std::endl;
}
