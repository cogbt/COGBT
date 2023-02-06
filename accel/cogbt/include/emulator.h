#ifndef EMULATOR_H
#define EMULATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

extern int aotmode;

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

int GuestFPUOffset(int idx);
int GuestST0Offset(void *p);

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
void helper_comiss_wrapper(void *p, int dest, int src);
void helper_comisd_wrapper(void *p, int dest, int src);
void helper_minsd_wrapper(void *p, int dest, int src);
void helper_paddb_xmm_wrapper(void *p, int dest, int src);
void helper_paddl_xmm_wrapper(void *p, int dest, int src);
void helper_paddw_xmm_wrapper(void *p, int dest, int src);
void helper_paddq_xmm_wrapper(void *p, int dest, int src);
void helper_cvtsi2sd_wrapper(void *p, int dest, int64_t val);
void helper_cvtsq2sd_wrapper(void *p, int dest, int64_t val);
int32_t helper_cvttsd2si_wrapper(void *p, int src);
int64_t helper_cvttsd2sq_wrapper(void *p, int src);
void helper_mulsd_wrapper(void *p, int dest, int src);
void helper_addsd_wrapper(void *p, int dest, int src);
void helper_fucomi_ST0_FT0_wrapper(void *p);
void helper_fcomi_ST0_FT0_wrapper(void *p);
void helper_cogbt_lookup_tb_ptr_wrapper(void *p);

struct KeyVal {
    const char *key;
    void *val;
};

extern struct KeyVal SymTable[];
extern int SymTableSize;

#ifdef __cplusplus
}
#endif

#endif
