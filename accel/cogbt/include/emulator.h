#ifndef EMULATOR_H
#define EMULATOR_H

#ifdef __cplusplus
extern "C" {
#endif

int GuestStateOffset(int Idx);
int GuestEflagOffset(void);

#ifdef __cplusplus
}
#endif

#endif
