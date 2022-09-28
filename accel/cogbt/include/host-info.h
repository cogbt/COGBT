#ifndef HOST_INFO_H
#define HOST_INFO_H

/* #define NumHostRegs 32 */
#define NumHostCSRs 11

enum HostRegsID {
    HostZero = 0,
    HostRA,
    HostTP,
    HostSP,
    HostA0,
    HostA1,
    HostA2,
    HostA3,
    HostA4,
    HostA5,
    HostA6,
    HostA7,
    HostT0,
    HostT1,
    HostT2,
    HostT3,
    HostT4,
    HostT5,
    HostT6,
    HostT7,
    HostT8,
    HostX,
    HostFP,
    HostS0,
    HostS1,
    HostS2,
    HostS3,
    HostS4,
    HostS5,
    HostS6,
    HostS7,
    HostS8,

    NumHostRegs
};

/* #define HostRA 1 */
/* #define HostSP 3 */
/* #define HostA0 4 */
/* #define HostA1 5 */
/* #define HostA2 6 */
/* #define HostA3 7 */
/* #define HostA4 8 */
/* #define HostA5 9 */
/* #define HostA6 10 */
/* #define HostA7 11 */
/* #define HostFP 22 */
/* #define HostS0 23 */
/* #define HostS1 24 */
/* #define HostS2 25 */
/* #define HostS3 26 */
/* #define HostS4 27 */
/* #define HostS5 28 */
/* #define HostS6 29 */
/* #define HostS7 30 */
/* #define HostS8 31 */

/// Host specially used registers
#define ENVReg HostS2
#define EFLAGReg HostFP

extern const char *HostRegNames[];
extern const int HostCSRs[];

#endif
