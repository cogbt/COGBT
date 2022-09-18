#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "emulator.h"

int GuestStateOffset(int idx) {
    return offsetof(CPUX86State, regs[idx]);
}

int GuestEflagOffset(void) {
    return offsetof(CPUX86State, eflags);
}
