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
        return offsetof(CPUX86State, segs[0]);
    case X86_REG_CS:
        return offsetof(CPUX86State, segs[1]);
    case X86_REG_SS:
        return offsetof(CPUX86State, segs[2]);
    case X86_REG_DS:
        return offsetof(CPUX86State, segs[3]);
    case X86_REG_FS:
        return offsetof(CPUX86State, segs[4]);
    case X86_REG_GS:
        return offsetof(CPUX86State, segs[5]);
    default:
        fprintf(stderr, "It's not a seg reg!\n");
        abort();
    }
}

int GuestEIPOffset(void) {
    return offsetof(CPUX86State, eip);
}
