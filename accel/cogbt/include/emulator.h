#ifndef EMULATOR_H
#define EMULATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int GetEAXOffset(void);
int GetEBXOffset(void);
int GetECXOffset(void);
int GetEDXOffset(void);
int GuestStateOffset(int Idx);
int GuestEflagOffset(void);
int GuestSegOffset(int SegIdx);
int GuestEIPOffset(void);

void helper_raise_syscall(void *p, uint64_t next_eip);
void helper_divb_AL_wrapper(void *p, uint64_t divisor);
void helper_divw_AX_wrapper(void *p, uint64_t divisor);
void helper_divl_EAX_wrapper(void *p, uint64_t divisor);
#ifdef __cplusplus
}
#endif

#endif
