#ifndef HOST_INFO_H
#define HOST_INFO_H

#define NumHostRegs 32
#define NumHostCSRs 11

#define HostRA 1
#define HostSP 3
#define HostA0 4
#define HostA1 5
#define HostA2 6
#define HostA3 7
#define HostA4 8
#define HostA5 9
#define HostA6 10
#define HostA7 11
#define HostFP 22
#define HostS0 23
#define HostS1 24
#define HostS2 25
#define HostS3 26
#define HostS4 27
#define HostS5 28
#define HostS6 29
#define HostS7 30
#define HostS8 31

/// Host specially used registers
#define ENVReg HostS2
#define EFLAGReg HostFP

extern const char *HostRegNames[];
extern const int HostCSRs[];

#endif
