#include "host-info.h"

const char *HostRegNames[] = {
    "$r0",  "$r1",  "$r2",  "$r3",  "$r4",  "$r5",  "$r6",  "$r7",
    "$r8",  "$r9",  "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
    "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
    "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
};

const int HostCSRs[] = {
    HostRA, HostFP, HostS0, HostS1, HostS2, HostS3, HostS4, HostS5,
    HostS6, HostS7, HostS8
};

const char *HostFPRegNames[] = {
    "$fcc0",  "$fcc1",  "$fcc2",  "$fcc3",  "$fcc4",  "$fcc5",  "$fcc6",  "$fcc7",
    "$fcc8",  "$fcc9",  "$fcc10", "$fcc11", "$fcc12", "$fcc13", "$fcc14", "$fcc15",
    "$fcc16", "$fcc17", "$fcc18", "$fcc19", "$fcc20", "$fcc21", "$fcc22", "$fcc23",
    "$fcc24", "$fcc25", "$fcc26", "$fcc27", "$fcc28", "$fcc29", "$fcc30", "$fcc31",
};

const char *HostLSXRegNames[] = {
    "$vr0",  "$vr1",  "$vr2",  "$vr3",  "$vr4",  "$vr5",  "$vr6",  "$vr7",
    "$vr8",  "$vr9",  "$vr10", "$vr11", "$vr12", "$vr13", "$vr14", "$vr15",
    "$vr16", "$vr17", "$vr18", "$vr19", "$vr20", "$vr21", "$vr22", "$vr23",
    "$vr24", "$vr25", "$vr26", "$vr27", "$vr28", "$vr29", "$vr30", "$vr31",
};

const char *HostLASXRegNames[] = {
    "$xr0",  "$xr1",  "$xr2",  "$xr3",  "$xr4",  "$xr5",  "$xr6",  "$xr7",
    "$xr8",  "$xr9",  "$xr10", "$xr11", "$xr12", "$xr13", "$xr14", "$xr15",
    "$xr16", "$xr17", "$xr18", "$xr19", "$xr20", "$xr21", "$xr22", "$xr23",
    "$xr24", "$xr25", "$xr26", "$xr27", "$xr28", "$xr29", "$xr30", "$xr31",
};

const int HostLSXCSRs[] = {
    HostF24, HostF25, HostF26, HostF27, HostF28, HostF29, HostF30, HostF31
};
