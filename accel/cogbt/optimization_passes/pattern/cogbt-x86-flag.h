#ifndef __COGBT_PASS_X86_FLAG__H
#define __COGBT_PASS_X86_FLAG__H

#include <cstdint>

typedef struct {
    uint8_t use;
    uint8_t def;
    uint8_t undef;
} FLAG_USEDEF;

#define __CF (1ULL << 0)
#define __PF (1ULL << 1)
#define __AF (1ULL << 2)
#define __ZF (1ULL << 3)
#define __SF (1ULL << 4)
#define __OF (1ULL << 5)
// Loongarch64 LBT does not involve this Bits in FLAG register
#define __DF (1ULL << 6)

#define __NONE       (0)
#define __OSAPF      (__OF | __SF | __AF | __PF)
#define __SZAPF      (__SF | __ZF | __AF | __PF)
#define __SZAPCF     (__SZAPF | __CF)
#define __ALL_FLAGS  (__OF | __SF | __ZF | __AF | __PF | __CF)
#define __INSTR_REMOVE (0xff)

#define HANDLE_IR_NAME(str) "llvm.loongarch." # str

#define IR_WITH_BHWD(str, use, def, undef) \
    {HANDLE_IR_NAME(str) ".b", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".h", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".w", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".d", {use, def, undef}},
#define IR_WITH_BHWDU(str, use, def, undef) \
    {HANDLE_IR_NAME(str) ".bu", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".hu", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".wu", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".du", {use, def, undef}},
#define IR_WITH_WDU(str, use, def, undef) \
    {HANDLE_IR_NAME(str) ".wu", {use, def, undef}}, \
    {HANDLE_IR_NAME(str) ".du", {use, def, undef}},

/* #define IR_WITH_BHWD(str, use, def, undef) \ */
/*     {HANDLE_IR_NAME(str) ".d", {use, def, undef}}, */
/* #define IR_WITH_BHWDU(str, use, def, undef) \ */
/*     {HANDLE_IR_NAME(str) ".du", {use, def, undef}}, */
/* #define IR_WITH_WDU(str, use, def, undef) \ */
/*     {HANDLE_IR_NAME(str) ".du", {use, def, undef}}, */
 
#define IR_WITHOUT_TY(str, use, def, undef) \
    {HANDLE_IR_NAME(str), {use, def, undef}},

#endif  // __COGBT_PASS_X86_FLAG__H
