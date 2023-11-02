#ifndef HOST_INFO_H
#define HOST_INFO_H

/* #define NumHostRegs 32 */

/* Callee-Saved Register */
#define NumHostCSRs 11
#define NumHostLSXCSRs 8

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
    NumHostRegs,

    HostF0 = 0,
    HostF1,
    HostF2,
    HostF3,
    HostF4,
    HostF5,
    HostF6,
    HostF7,
    HostF8,
    HostF9,
    HostF10,
    HostF11,
    HostF12,
    HostF13,
    HostF14,
    HostF15,
    HostF16,
    HostF17,
    HostF18,
    HostF19,
    HostF20,
    HostF21,
    HostF22,
    HostF23,
    HostF24,
    HostF25,
    HostF26,
    HostF27,
    HostF28,
    HostF29,
    HostF30,
    HostF31,
    NumHostFPRegs,

    HostV0 = 0,
    HostV1,
    HostV2,
    HostV3,
    HostV4,
    HostV5,
    HostV6,
    HostV7,
    HostV8,
    HostV9,
    HostV10,
    HostV11,
    HostV12,
    HostV13,
    HostV14,
    HostV15,
    HostV16,
    HostV17,
    HostV18,
    HostV19,
    HostV20,
    HostV21,
    HostV22,
    HostV23,
    HostV24,
    HostV25,
    HostV26,
    HostV27,
    HostV28,
    HostV29,
    HostV30,
    HostV31,
    NumHostLSXRegs,

    HostX0 = 0,
    HostX1,
    HostX2,
    HostX3,
    HostX4,
    HostX5,
    HostX6,
    HostX7,
    HostX8,
    HostX9,
    HostX10,
    HostX11,
    HostX12,
    HostX13,
    HostX14,
    HostX15,
    HostX16,
    HostX17,
    HostX18,
    HostX19,
    HostX20,
    HostX21,
    HostX22,
    HostX23,
    HostX24,
    HostX25,
    HostX26,
    HostX27,
    HostX28,
    HostX29,
    HostX30,
    HostX31,
    NumHostLASXRegs,
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
extern const char *HostFPRegNames[];
extern const char *HostLSXRegNames[];
extern const char *HostLASXRegNames[];
extern const int HostLSXCSRs[];

#endif
