#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "emulator.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "target/i386/tcg/helper-tcg.h"
#include "x86.h"

/* #include "exec/log.h" */

int GetEAXOffset(void) { return GuestStateOffset(R_EAX); }
int GetEBXOffset(void) { return GuestStateOffset(R_EBX); }
int GetECXOffset(void) { return GuestStateOffset(R_ECX); }
int GetEDXOffset(void) { return GuestStateOffset(R_EDX); }

int GuestStateOffset(int idx) {
    return offsetof(CPUX86State, regs[idx]);
}

int GuestEflagOffset(void) {
    return offsetof(CPUX86State, eflags);
}

int GuestXMMT0Offset(void) {
    return offsetof(CPUX86State, xmm_t0);
}

int GuestMMXT0Offset(void) {
    return offsetof(CPUX86State, mmx_t0);
}

int GuestXMMOffset(int idx) {
    return offsetof(CPUX86State, xmm_regs[idx]);
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

int GuestEIPOffset(void) {
    return offsetof(CPUX86State, eip);
}

void helper_raise_syscall(void *p, uint64_t next_eip) {
    CPUX86State *env = (CPUX86State *)p;
    CPUState *cpu = env_cpu(env);
    cpu->exception_index = EXCP_SYSCALL;
    cpu->can_do_io = 1;
    env->exception_is_int = 0;
    env->exception_next_eip = next_eip;
    siglongjmp(cpu->jmp_env, 1);
}

/* extern void helper_divb_AL(CPUX86State *env, target_ulong t0); */
/* extern void helper_divw_AX(CPUX86State *env, target_ulong t0); */
/* extern void helper_divl_EAX(CPUX86State *env, target_ulong t0); */
/* extern void helper_divq_EAX(CPUX86State *env, target_ulong t0); */

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

/* extern void helper_rdtsc(CPUArchState *env); */
void helper_rdtsc_wrapper(void *p) {
    helper_rdtsc((CPUX86State *)p);
}

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
    /* CPUX86State *env = (CPUX86State *)p; */
    /* Reg *d = &env->mmx_regs[dest]; */
    /* Reg *s = &env->mmx_t0; */
    /* if (src != -1) { // src is not memory */
    /*     &env->mmx_regs[src]; */
    /* } */
    /* helper_pxor_xmm(env, d, s); */
}
