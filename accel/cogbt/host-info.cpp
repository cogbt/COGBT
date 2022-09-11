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
