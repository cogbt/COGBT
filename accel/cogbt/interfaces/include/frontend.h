#ifndef JSON_HANDLE_H
#define JSON_HANDLE_H

#include <memory>
#include "json_function.h"

enum JSON_MODE {
    JSON_GHIDRA     = 1      ,   // from ghidra
    JSON_FUNC_TXT   = 1 << 1 ,   // from cogbt, reusable
    JSON_TRACE      = 1 << 2 ,   // from trace collect
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
// json_funcs_sort - Sort by the entry point of JsonFuncs.
void json_funcs_sort(vector<shared_ptr<JsonFunc>> &JsonFuncs, int start = 0);
// check_json_funcs - Check array of JsonFuncs for identical entry point of JsonFunc.
void check_json_funcs(vector<shared_ptr<JsonFunc>> &JsonFuncs, const char* message);

// block_parse - Parse file `pf`, and regard the pc in it as the entry of JsonFunc,
//  and then add them into JsonFuncs.
void block_parse(const char *pf, vector<shared_ptr<JsonFunc>> &JsonFuncs);

// GenTU - Handle JF and formalize it tu TU.
void GenTU(shared_ptr<JsonFunc> JF, TranslationUnit *TU);

void capstone_init(void);
#endif
