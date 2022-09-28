#include "x86-config.h"
#include "host-info.h"

const char *X86Config::X86RegName[NumX64MappedRegs] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "eflag",
};

const int X86Config::X86RegToHost[NumX64MappedRegs] = {
    HostT3, HostT6, HostT7, HostS3, HostS4, HostS5, HostS6, HostS7,
    HostS1, HostS8, HostA6, HostA7, HostT0, HostT1, HostT2, HostS0,
    HostFP,
};

