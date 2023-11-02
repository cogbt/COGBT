#include "x86-config.h"
#include "host-info.h"

const char *X86Config::X86GPRName[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "eflag",
};

const int X86Config::X86GPRToHost[] = {
    HostT3, HostT6, HostT7, HostS3, HostS4, HostS5, HostS6, HostS7,
    HostS1, HostS8, HostA6, HostA7, HostT0, HostT1, HostT2, HostS0,
    HostFP,
};

const char *X86Config::X64XMMRegName[] = {
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
};

const int X86Config::X64XMMRegToHost[] = {
    HostV16, HostV17, HostV18, HostV19, HostV20, HostV21, HostV22, HostV23,
    HostV24, HostV25, HostV26, HostV27, HostV28, HostV29, HostV30, HostV31
};

const int X86Config::RegTypeSize[] = {
    [X86RegGPRType] = 64,
    [X86RegXMMType] = 128,
};
