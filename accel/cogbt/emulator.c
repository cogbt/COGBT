#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "emulator.h"
#include "x86.h"

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

extern void helper_divb_AL(CPUX86State *env, target_ulong t0);
extern void helper_divw_AX(CPUX86State *env, target_ulong t0);
extern void helper_divl_EAX(CPUX86State *env, target_ulong t0);
extern void helper_divq_EAX(CPUX86State *env, target_ulong t0);

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

extern void helper_rdtsc(CPUArchState *env);
void helper_rdtsc_wrapper(void *p) {
    helper_rdtsc((CPUX86State *)p);
}
