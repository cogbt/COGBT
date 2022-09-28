#ifndef GUEST_CONFIG_H
#define GUEST_CONFIG_H

#include "llvm/ADT/StringRef.h"
using llvm::StringRef;

class GuestConfig {
public:
    virtual ~GuestConfig() = default;

    /// GetNumGMRs - Get the number of guest mapped registers. For each GMR, a
    /// llvm stack object is allocated to cache its state.
    virtual int GetNumGMRs() = 0;

    virtual int GetNumSpecialGMRs() = 0;

    /// GetGMRName - Get the name of the GMR.
    virtual const char *GetGMRName(int id) = 0;

    /// GMRToHMR - Get the host mapped register of a guest mapped register.
    virtual int GMRToHMR(int gid) = 0;
};

#endif
