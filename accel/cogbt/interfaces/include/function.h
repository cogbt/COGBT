#ifndef FUNCTION_H
#define FUNCTION_H

#include <stdint.h>
#include <capstone.h>
#include "cogbt.h"

#ifdef __cplusplus
extern "C" {
#endif

/// cogbt_function_init - Initialze cogbt function tu mode.
void cogbt_function_init(void);
/// cogbt_function_fini - Finalize cogbt function tu mode.
void cogbt_function_fini(void);

/// func_tu_json_parse - Parse function translation unit json file.
void func_tu_json_parse(const char *pf);

/// aot_gen - Generate final AOT.
void aot_gen(const char *pf);

#ifdef __cplusplus
}
#endif

#endif
