#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "target/i386/tcg/helper-tcg.h"
#include "x86.h"
#include "emulator.h"

struct KeyVal SymTable[] = {
    {"helper_fstt_ST0_From64", helper_fstt_ST0_From64_wrapper},
    {"helper_fldt_ST0_To64", helper_fldt_ST0_To64_wrapper},
    {"helper_fpatan_math_64", helper_fpatan_math_64_wrapper},
    {"helper_fcom_ST0_zero_64", helper_fcom_ST0_zero_64_wrapper},
    // {"helper_f2xm1_64", helper_f2xm1_64_wrapper},
    {"helper_round_mode", helper_round_mode_wrapper},
    {"helper_divb_AL", helper_divb_AL_wrapper},
    {"helper_divw_AX", helper_divw_AX_wrapper},
    {"helper_divl_EAX", helper_divl_EAX_wrapper},
    {"helper_divq_EAX", helper_divq_EAX_wrapper},
    {"helper_idivb_AL", helper_idivb_AL_wrapper},
    {"helper_idivw_AX", helper_idivw_AX_wrapper},
    {"helper_idivl_EAX", helper_idivl_EAX_wrapper},
    {"helper_idivq_EAX", helper_idivq_EAX_wrapper},

    {"helper_rdtsc", helper_rdtsc_wrapper},
    /* {"helper_pxor_xmm", helper_pxor_xmm_wrapper}, */
    /* {"helper_pxor_mmx", helper_pxor_mmx_wrapper}, */
    /* {"helper_pcmpeqb_xmm", helper_pcmpeqb_xmm_wrapper}, */
    /* {"helper_pcmpeqb_mmx", helper_pcmpeqb_mmx_wrapper}, */
    // {"helper_pmovmskb_xmm", helper_pmovmskb_xmm_wrapper},
    // {"helper_pmovmskb_mmx", helper_pmovmskb_mmx_wrapper},
    // {"helper_punpcklbw_xmm", helper_punpcklbw_xmm_wrapper},
    // {"helper_punpcklbw_mmx", helper_punpcklbw_mmx_wrapper},
    // {"helper_punpcklwd_xmm", helper_punpcklwd_xmm_wrapper},
    // {"helper_punpcklwd_mmx", helper_punpcklwd_mmx_wrapper},
    {"helper_pshufd", helper_pshufd_xmm_wrapper},
    {"helper_comiss", helper_comiss_wrapper},
    {"helper_comisd", helper_comisd_wrapper},
    {"helper_minsd", helper_minsd_wrapper},
    {"helper_minss", helper_minss_wrapper},
    /* {"helper_paddb_xmm", helper_paddb_xmm_wrapper}, */
    /* {"helper_paddl_xmm", helper_paddl_xmm_wrapper}, */
    /* {"helper_paddw_xmm", helper_paddw_xmm_wrapper}, */
    /* {"helper_paddq_xmm", helper_paddq_xmm_wrapper}, */
    {"helper_cvtsi2sd", helper_cvtsi2sd_wrapper},
    {"helper_cvtsq2sd", helper_cvtsq2sd_wrapper},
    {"helper_cvttsd2si", helper_cvttsd2si_wrapper},
    {"helper_cvttsd2sq", helper_cvttsd2sq_wrapper},
    {"helper_cvttss2si", helper_cvttss2si_wrapper},
    {"helper_cvttss2sq", helper_cvttss2sq_wrapper},
    {"helper_cvtss2sd", helper_cvtss2sd_wrapper},
    {"helper_cvtsd2ss", helper_cvtsd2ss_wrapper},
    {"helper_cvtsi2ss", helper_cvtsi2ss_wrapper},
    {"helper_cvtsq2ss", helper_cvtsq2ss_wrapper},
    {"helper_mulsd", helper_mulsd_wrapper},
    {"helper_mulss", helper_mulss_wrapper},
    {"helper_divsd", helper_divsd_wrapper},
    {"helper_divss", helper_divss_wrapper},
    {"helper_subsd", helper_subsd_wrapper},
    {"helper_subss", helper_subss_wrapper},
    {"helper_sqrtsd", helper_sqrtsd_wrapper},
    {"helper_sqrtss", helper_sqrtss_wrapper},
    {"helper_maxsd", helper_maxsd_wrapper},
    {"helper_maxss", helper_maxss_wrapper},
    {"helper_addsd", helper_addsd_wrapper},
    {"helper_addss", helper_addss_wrapper},
    {"helper_xorpd", helper_xorpd_wrapper},
    {"helper_xorps", helper_xorps_wrapper},
    {"helper_andpd", helper_andpd_wrapper},
    {"helper_andps", helper_andps_wrapper},
    {"helper_pslldq_xmm", helper_pslldq_xmm_wrapper},
    {"helper_psrldq_xmm", helper_psrldq_xmm_wrapper},
    {"helper_fcomi_ST0_FT0_cogbt", helper_fcomi_ST0_FT0_wrapper},
    {"helper_fucomi_ST0_FT0_cogbt", helper_fucomi_ST0_FT0_wrapper},
#define SSE_HELPER_CMP_BINDING(name)                                           \
    {"helper_" #name "ps", helper_##name##ps_wrapper},                         \
        {"helper_" #name "ss", helper_##name##ss_wrapper},                     \
        {"helper_" #name "pd", helper_##name##pd_wrapper},                     \
        {"helper_" #name "sd", helper_##name##sd_wrapper},
    SSE_HELPER_CMP_BINDING(cmpeq) SSE_HELPER_CMP_BINDING(cmplt)
        SSE_HELPER_CMP_BINDING(cmple) SSE_HELPER_CMP_BINDING(cmpunord)
            SSE_HELPER_CMP_BINDING(cmpneq) SSE_HELPER_CMP_BINDING(cmpnlt)
                SSE_HELPER_CMP_BINDING(cmpnle) SSE_HELPER_CMP_BINDING(cmpord)

                    {"helper_raise_syscall", helper_raise_syscall},
    {"helper_cogbt_lookup_tb_ptr", helper_cogbt_lookup_tb_ptr},
};

int SymTableSize = sizeof(SymTable) / sizeof(SymTable[0]);

/* #include "exec/log.h" */

int GetEAXOffset(void) { return GuestStateOffset(R_EAX); }
int GetEBXOffset(void) { return GuestStateOffset(R_EBX); }
int GetECXOffset(void) { return GuestStateOffset(R_ECX); }
int GetEDXOffset(void) { return GuestStateOffset(R_EDX); }

int GuestStateOffset(int idx) { return offsetof(CPUX86State, regs[idx]); }

int GuestEflagOffset(void) { return offsetof(CPUX86State, eflags); }

int GuestXMMT0Offset(void) { return offsetof(CPUX86State, xmm_t0); }

int GuestXMMT0Offset_bytes(int reg_start_byte) {
    return offsetof(CPUX86State, xmm_t0.ZMM_B(reg_start_byte));
}

int GuestMMXT0Offset(void) { return offsetof(CPUX86State, mmx_t0); }

int GuestXMMOffset(int idx) { return offsetof(CPUX86State, xmm_regs[idx]); }

int GuestMMXOffset(int idx) { return offsetof(CPUX86State, fpregs[idx].mmx); }

int GuestFPUOffset(int idx) { return offsetof(CPUX86State, fpregs[idx].d); }

int GuestFpsttOffset(void) { return offsetof(CPUX86State, fpstt); }

int GuestFPRegSize(void) { return sizeof(FPReg); }

int GuestFpTagSize(void) { return sizeof(uint8_t); }

int GuestFpTagOffset(void) { return offsetof(CPUX86State, fptags); }

int GuestFpregsOffset(void) { return offsetof(CPUX86State, fpregs); }

int GuestFpusOffset(void) { return offsetof(CPUX86State, fpus); }

int GuestFpucOffset(void) { return offsetof(CPUX86State, fpuc); }

int GuestFT0Offset(void) { return offsetof(CPUX86State, ft0); }

int GuestFpusSize(void) { return sizeof(uint16_t); };

int GuestST0Offset(void *p) {
    CPUX86State *env = (CPUX86State *)p;
    return GuestFPUOffset(env->fpstt);
}

int GuestSegOffset(int seg_idx) {
    switch (seg_idx) {
    case X86_REG_ES:
        return offsetof(CPUX86State, segs[0].base);
    case X86_REG_CS:
        return offsetof(CPUX86State, segs[1].base);
    case X86_REG_SS:
        return offsetof(CPUX86State, segs[2].base);
    case X86_REG_DS:
        return offsetof(CPUX86State, segs[3].base);
    case X86_REG_FS:
        return offsetof(CPUX86State, segs[4].base);
    case X86_REG_GS:
        return offsetof(CPUX86State, segs[5].base);
    default:
        fprintf(stderr, "It's not a seg reg!\n");
        abort();
    }
}

int GuestEIPOffset(void) { return offsetof(CPUX86State, eip); }

int GuestZMMRegOffset(int reg_idx, int reg_start_byte) {
    return offsetof(CPUX86State, xmm_regs[reg_idx].ZMM_B(reg_start_byte));
}

int GuestMMXRegOffset(int reg_idx, int reg_start_byte) {
    return offsetof(CPUX86State, fpregs[reg_idx].mmx.MMX_B(reg_start_byte));
}

int GuestMXCSROffset(void) { return offsetof(CPUX86State, mxcsr); }

void helper_raise_syscall(void *p, uint64_t next_eip) {
    CPUX86State *env = (CPUX86State *)p;
    CPUState *cpu = env_cpu(env);
    cpu->exception_index = EXCP_SYSCALL;
    cpu->can_do_io = 1;
    env->exception_is_int = 0;
    env->exception_next_eip = next_eip;
    last_exit_is_llvm = true;
    siglongjmp(cpu->jmp_env, 1);
}

/* extern void helper_divb_AL(CPUX86State *env, target_ulong t0); */
/* extern void helper_divw_AX(CPUX86State *env, target_ulong t0); */
/* extern void helper_divl_EAX(CPUX86State *env, target_ulong t0); */
/* extern void helper_divq_EAX(CPUX86State *env, target_ulong t0); */

void helper_fpatan_math_64_wrapper(void *p) {
    helper_fpatan_math_64((CPUX86State *)p);
}

void helper_fcom_ST0_zero_64_wrapper(void *p) {
    helper_fcom_ST0_zero_64((CPUX86State *)p);
}

void helper_fstt_ST0_From64_wrapper(void *p, uint64_t ptr) {

    helper_fstt_ST0_From64((CPUX86State *)p, ptr);
}
void helper_fldt_ST0_To64_wrapper(void *p, uint64_t ptr) {

    helper_fldt_ST0_To64((CPUX86State *)p, ptr);
}

// void helper_f2xm1_64_wrapper(void *p){
//     helper_f2xm1_64((CPUX86State *)p);
// }

void helper_divb_AL_wrapper(void *p, uint64_t divisor) {
    helper_divb_AL((CPUX86State *)p, divisor);
}
void helper_divw_AX_wrapper(void *p, uint64_t divisor) {
    helper_divw_AX((CPUX86State *)p, divisor);
}
void helper_divl_EAX_wrapper(void *p, uint64_t divisor) {
    helper_divl_EAX((CPUX86State *)p, divisor);
}
void helper_divq_EAX_wrapper(void *p, uint64_t divisor) {
    helper_divq_EAX((CPUX86State *)p, divisor);
}
void helper_idivb_AL_wrapper(void *p, uint64_t divisor) {
    helper_idivb_AL((CPUX86State *)p, divisor);
}
void helper_idivw_AX_wrapper(void *p, uint64_t divisor) {
    helper_idivw_AX((CPUX86State *)p, divisor);
}
void helper_idivl_EAX_wrapper(void *p, uint64_t divisor) {
    helper_idivl_EAX((CPUX86State *)p, divisor);
}
void helper_idivq_EAX_wrapper(void *p, uint64_t divisor) {
    helper_idivq_EAX((CPUX86State *)p, divisor);
}

/* extern void helper_rdtsc(CPUArchState *env); */
void helper_rdtsc_wrapper(void *p) { helper_rdtsc((CPUX86State *)p); }

void helper_pxor_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pxor_xmm(env, d, s);
}
void helper_pxor_mmx_wrapper(void *p, int dest, int src) {
    assert(0 && "Unfinished pxor_mmx\n");
}

void helper_pcmpeqb_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pcmpeqb_xmm(env, d, s);
}
void helper_pcmpeqb_mmx_wrapper(void *p, int dest, int src) {
    assert(0 && "Unhandled pcmpeqb_mmx\n");
}
void helper_pmovmskb_xmm_wrapper(void *p, int index) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *s = &env->xmm_regs[index];
    helper_pmovmskb_xmm(env, s);
}
void helper_pmovmskb_mmx_wrapper(void *p, int index) {
    assert(0 && "Unhandled pmovmskb_mmx\n");
}

// void helper_punpcklbw_xmm_wrapper(void *p, int dest, int src) {
//     CPUX86State *env = (CPUX86State *)p;
//     ZMMReg *d = &env->xmm_regs[dest];
//     ZMMReg *s = &env->xmm_t0;
//     if (src != -1) { // src is not memory
//         s = &env->xmm_regs[src];
//     }
//     helper_punpcklbw_xmm(env, d, s);
// }
// void helper_punpcklbw_mmx_wrapper(void *p, int dest, int src) {
//     assert(0 && "Unfinished pxor_mmx\n");
// }

// void helper_punpcklwd_xmm_wrapper(void *p, int dest, int src) {
//     CPUX86State *env = (CPUX86State *)p;
//     ZMMReg *d = &env->xmm_regs[dest];
//     ZMMReg *s = &env->xmm_t0;
//     if (src != -1) { // src is not memory
//         s = &env->xmm_regs[src];
//     }
//     helper_punpcklwd_xmm(env, d, s);
// }

// void helper_punpcklwd_mmx_wrapper(void *p, int dest, int src) {
//     assert(0 && "Unfinished pxor_mmx\n");
// }

void helper_pshufd_xmm_wrapper(void *p, int dest, int src, int order) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_regs[src];
    helper_pshufd_xmm(d, s, order);
}

void helper_comiss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) {
        s = &env->xmm_regs[src];
    }
    helper_comiss(env, d, s);
}

void helper_comisd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) {
        s = &env->xmm_regs[src];
    }
    helper_comisd(env, d, s);
}

void helper_minsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) {
        s = &env->xmm_regs[src];
    }
    helper_minsd(env, d, s);
}

void helper_paddb_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_paddb_xmm(env, d, s);
}

void helper_paddw_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_paddw_xmm(env, d, s);
}

void helper_paddl_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_paddl_xmm(env, d, s);
}

void helper_paddq_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_paddq_xmm(env, d, s);
}

void helper_pslldq_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pslldq_xmm(env, d, s);
}

void helper_psrldq_xmm_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_psrldq_xmm(env, d, s);
}

void helper_cvtsi2sd_wrapper(void *p, int dest, int64_t val) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    helper_cvtsi2sd(env, d, val);
}

void helper_cvtsq2sd_wrapper(void *p, int dest, int64_t val) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    helper_cvtsq2sd(env, d, val);
}

void helper_mulsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_mulsd(env, d, s);
}

void helper_round_mode_wrapper(void *p) {
    CPUX86State *env = (CPUX86State *)p;
    helper_round_mode(env);
}

void helper_mulss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_mulss(env, d, s);
}

void helper_addsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_addsd(env, d, s);
}

void helper_divsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_divsd(env, d, s);
}

void helper_divss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_divss(env, d, s);
}

void helper_subsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_subsd(env, d, s);
}

void helper_subss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_subss(env, d, s);
}

void helper_sqrtsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_sqrtsd(env, d, s);
}

void helper_sqrtss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_sqrtss(env, d, s);
}

void helper_maxsd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_maxsd(env, d, s);
}

void helper_maxss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_maxss(env, d, s);
}

void helper_addss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_addss(env, d, s);
}

void helper_minss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_minss(env, d, s);
}

void helper_xorpd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pxor_xmm(env, d, s);
}

void helper_xorps_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pxor_xmm(env, d, s);
}

void helper_andpd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pand_xmm(env, d, s);
}

void helper_andps_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_pand_xmm(env, d, s);
}

void helper_fucomi_ST0_FT0_wrapper(void *p) {
    helper_fucomi_ST0_FT0_cogbt((CPUX86State *)p);
}

void helper_fcomi_ST0_FT0_wrapper(void *p) {
    helper_fcomi_ST0_FT0_cogbt((CPUX86State *)p);
}

void helper_cogbt_lookup_tb_ptr_wrapper(void *p) {
    helper_cogbt_lookup_tb_ptr((CPUX86State *)p);
}

int32_t helper_cvttsd2si_wrapper(void *p, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    return helper_cvttsd2si(env, s);
}

int64_t helper_cvttsd2sq_wrapper(void *p, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    return helper_cvttsd2sq(env, s);
}

int32_t helper_cvttss2si_wrapper(void *p, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    return helper_cvttss2si(env, s);
}

int64_t helper_cvttss2sq_wrapper(void *p, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    return helper_cvttss2sq(env, s);
}

void helper_cvtss2sd_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_cvtss2sd(env, d, s);
}

void helper_cvtsd2ss_wrapper(void *p, int dest, int src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    ZMMReg *s = &env->xmm_t0;
    if (src != -1) { // src is not memory
        s = &env->xmm_regs[src];
    }
    helper_cvtsd2ss(env, d, s);
}

void helper_cvtsi2ss_wrapper(void *p, int dest, int64_t src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    helper_cvtsi2ss(env, d, src);
}

void helper_cvtsq2ss_wrapper(void *p, int dest, int64_t src) {
    CPUX86State *env = (CPUX86State *)p;
    ZMMReg *d = &env->xmm_regs[dest];
    helper_cvtsq2ss(env, d, src);
}

#define SSE_HELPER_CMP_WRAPPER(name)                                           \
    void helper_##name##ps_wrapper(void *p, int dest, int src) {               \
        CPUX86State *env = (CPUX86State *)p;                                   \
        ZMMReg *d = &env->xmm_regs[dest];                                      \
        ZMMReg *s = &env->xmm_regs[src];                                       \
        helper_##name##ps(env, d, s);                                          \
    }                                                                          \
    void helper_##name##ss_wrapper(void *p, int dest, int src) {               \
        CPUX86State *env = (CPUX86State *)p;                                   \
        ZMMReg *d = &env->xmm_regs[dest];                                      \
        ZMMReg *s = &env->xmm_regs[src];                                       \
        helper_##name##ss(env, d, s);                                          \
    }                                                                          \
    void helper_##name##pd_wrapper(void *p, int dest, int src) {               \
        CPUX86State *env = (CPUX86State *)p;                                   \
        ZMMReg *d = &env->xmm_regs[dest];                                      \
        ZMMReg *s = &env->xmm_regs[src];                                       \
        helper_##name##pd(env, d, s);                                          \
    }                                                                          \
    void helper_##name##sd_wrapper(void *p, int dest, int src) {               \
        CPUX86State *env = (CPUX86State *)p;                                   \
        ZMMReg *d = &env->xmm_regs[dest];                                      \
        ZMMReg *s = &env->xmm_regs[src];                                       \
        helper_##name##sd(env, d, s);                                          \
    }

SSE_HELPER_CMP_WRAPPER(cmpeq)
SSE_HELPER_CMP_WRAPPER(cmplt)
SSE_HELPER_CMP_WRAPPER(cmple)
SSE_HELPER_CMP_WRAPPER(cmpunord)
SSE_HELPER_CMP_WRAPPER(cmpneq)
SSE_HELPER_CMP_WRAPPER(cmpnlt)
SSE_HELPER_CMP_WRAPPER(cmpnle)
SSE_HELPER_CMP_WRAPPER(cmpord)
