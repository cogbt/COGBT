#ifndef JSON_HANDLE_H
#define JSON_HANDLE_H

#include <memory>
#include "function.h"

enum JSON_MODE {
    JSON_ORIGIN     = 1      ,   // from ghidra
    JSON_FUNC_TXT   = 1 << 1 ,   // from cogbt, reusable
    JSON_TRACE      = 1 << 2    // from trace collect
};


/// ================== parse elf ======================= ///
// parse_elf_format - Parse elf .symtab
void parse_elf_format(const char*exec_path, vector<shared_ptr<JsonFunc>> 
        &JsonFuncs);

/// =============== parse json file ==================== ///
// json_parse - Parse json file.
void json_parse(const char *pf, vector<std::shared_ptr<JsonFunc>> &JsonFuncs,
        uint32_t mode);
// json_dump - Dump json file.
void json_dump(const char *pf, vector<std::shared_ptr<JsonFunc>> &JsonFuncs);

/// ================== utils ======================= ///
// json_funcs_search - Search func from JsonFuncs which EntryPoint is equal 
//  to target. JsonFuncs should sorted before calling this function.
int json_funcs_search(vector<shared_ptr<JsonFunc>> &JsonFuncs, uint64_t target);

#endif
