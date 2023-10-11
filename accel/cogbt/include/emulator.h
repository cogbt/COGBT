#ifndef EMULATOR_H
#define EMULATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

extern int aotmode;
extern char *exec_path;

int GetEAXOffset(void);
int GetEBXOffset(void);
int GetECXOffset(void);
int GetEDXOffset(void);
int GuestStateOffset(int Idx);
int GuestEflagOffset(void);
int GuestSegOffset(int SegIdx);
int GuestEIPOffset(void);
int GuestLoadbiasOffset(void);
int GuestXMMT0Offset(void);
int GuestMMXT0Offset(void);
int GuestXMMOffset(int idx);
int GuestMMXOffset(int idx);
int GuestZMMRegOffset(int reg_idx, int reg_start_byte);
int GuestMMXRegOffset(int reg_idx, int reg_start_byte);

int GuestFT0Offset(void);
int GuestFPUOffset(int idx);
int GuestST0Offset(void *p);

int GuestFpsttOffset(void);
int GuestFPRegSize(void);
int GuestFpregsOffset(void);
int GuestFpTagOffset(void);
int GuestFpTagSize(void);
int GuestFpusOffset(void);
int GuestFpusSize(void);
int GuestFpucSize(void);
int GuestFpucOffset(void);

int GuestMXCSROffset(void);

void helper_raise_syscall(void *p, uint64_t next_eip);
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
void helper_minss_wrapper(void *p, int dest, int src);
void helper_paddb_xmm_wrapper(void *p, int dest, int src);
void helper_paddl_xmm_wrapper(void *p, int dest, int src);
void helper_paddw_xmm_wrapper(void *p, int dest, int src);
void helper_paddq_xmm_wrapper(void *p, int dest, int src);
void helper_cvtsi2sd_wrapper(void *p, int dest, int64_t val);
void helper_cvtsq2sd_wrapper(void *p, int dest, int64_t val);
void helper_cvtss2sd_wrapper(void *p, int dest, int src);
void helper_cvtsd2ss_wrapper(void *p, int dest, int src);
void helper_cvtsi2ss_wrapper(void *p, int dest, int64_t src);
void helper_cvtsq2ss_wrapper(void *p, int dest, int64_t src);
int32_t helper_cvttsd2si_wrapper(void *p, int src);
int64_t helper_cvttsd2sq_wrapper(void *p, int src);
int32_t helper_cvttss2si_wrapper(void *p, int src);
int64_t helper_cvttss2sq_wrapper(void *p, int src);
void helper_mulsd_wrapper(void *p, int dest, int src);
void helper_mulss_wrapper(void *p, int dest, int src);
void helper_divsd_wrapper(void *p, int dest, int src);
void helper_divss_wrapper(void *p, int dest, int src);
void helper_subsd_wrapper(void *p, int dest, int src);
void helper_subss_wrapper(void *p, int dest, int src);
void helper_maxsd_wrapper(void *p, int dest, int src);
void helper_maxss_wrapper(void *p, int dest, int src);
void helper_sqrtsd_wrapper(void *p, int dest, int src);
void helper_sqrtss_wrapper(void *p, int dest, int src);
void helper_addsd_wrapper(void *p, int dest, int src);
void helper_addss_wrapper(void *p, int dest, int src);
void helper_cogbt_lookup_tb_ptr_wrapper(void *p);
void helper_xorpd_wrapper(void *p, int dest, int src);
void helper_xorps_wrapper(void *p, int dest, int src);
void helper_andpd_wrapper(void *p, int dest, int src);
void helper_andps_wrapper(void *p, int dest, int src);
void helper_pslldq_xmm_wrapper(void *p, int dest, int src);
void helper_psrldq_xmm_wrapper(void *p, int dest, int src);
#if 0
#define SSE_HELPER_CMP_WRAPPER_PROT(name)                       \
void helper_ ## name ## ps_wrapper(void *p, int dest, int src); \
void helper_ ## name ## ss_wrapper(void *p, int dest, int src); \
void helper_ ## name ## pd_wrapper(void *p, int dest, int src); \
void helper_ ## name ## sd_wrapper(void *p, int dest, int src);
SSE_HELPER_CMP_WRAPPER_PROT(cmpeq)
SSE_HELPER_CMP_WRAPPER_PROT(cmplt)
SSE_HELPER_CMP_WRAPPER_PROT(cmple)
SSE_HELPER_CMP_WRAPPER_PROT(cmpunord)
SSE_HELPER_CMP_WRAPPER_PROT(cmpneq)
SSE_HELPER_CMP_WRAPPER_PROT(cmpnlt)
SSE_HELPER_CMP_WRAPPER_PROT(cmpnle)
SSE_HELPER_CMP_WRAPPER_PROT(cmpord)
#endif

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
