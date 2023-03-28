#ifndef JSON_HANDLE_H
#define JSON_HANDLE_H

#include "function.h"

// json_parse - Parse json file.
void json_parse(const char *pf, vector<JsonFunc> &JsonFuncs);
// json_dump - Dump json file.
void json_dump(const char *pf, vector<JsonFunc> &JsonFuncs);

#endif
