#ifndef EMULATOR_H
#define EMULATOR_H

#ifdef __cplusplus
extern "C" {
#endif

int GetEAXOffset(void);
int GetEBXOffset(void);
int GetECXOffset(void);
int GetEDXOffset(void);
int GuestStateOffset(int Idx);
int GuestEflagOffset(void);
int GuestSegOffset(int SegIdx);
int GuestEIPOffset(void);

void helper_raise_syscall(void *env);
#ifdef __cplusplus
}
#endif

#endif
