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
int GuestXMMT0Offset(void);
int GuestMMXT0Offset(void);
int GuestXMMOffset(int idx);

void helper_raise_syscall(void *p, uint64_t next_eip);
void helper_divb_AL_wrapper(void *p, uint64_t divisor);
void helper_divw_AX_wrapper(void *p, uint64_t divisor);
void helper_divl_EAX_wrapper(void *p, uint64_t divisor);
void helper_divq_EAX_wrapper(void *p, uint64_t divisor);
void helper_idivb_AL_wrapper(void *p, uint64_t divisor);
void helper_idivw_AX_wrapper(void *p, uint64_t divisor);
void helper_idivl_EAX_wrapper(void *p, uint64_t divisor);
void helper_idivq_EAX_wrapper(void *p, uint64_t divisor);
void helper_rdtsc_wrapper(void *p);
void helper_pxor_xmm_wrapper(void *p, int dest, int src);
void helper_pxor_mmx_wrapper(void *p, int dest, int src);
void helper_pcmpeqb_xmm_wrapper(void *p, int dest, int src);
void helper_pcmpeqb_mmx_wrapper(void *p, int dest, int src);
void helper_pmovmskb_xmm_wrapper(void *p, int index);
void helper_pmovmskb_mmx_wrapper(void *p, int index);
void helper_punpcklbw_xmm_wrapper(void *p, int dest, int src);
void helper_punpcklbw_mmx_wrapper(void *p, int dest, int src);
void helper_punpcklwd_xmm_wrapper(void *p, int dest, int src);
void helper_punpcklwd_mmx_wrapper(void *p, int dest, int src);
void helper_pshufd_xmm_wrapper(void *p, int dest, int src, int order);
#ifdef __cplusplus
}
#endif

#endif
