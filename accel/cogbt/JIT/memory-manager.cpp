#include "memory-manager.h"

uint8_t *COGBTMemoryManager::allocateCodeSection(uintptr_t Size,
                                                 unsigned Alignment,
                                                 unsigned SectionID,
                                                 StringRef SectionName) {
    if (!Alignment)
        Alignment = 16;
    assert(!(Alignment & (Alignment - 1)) &&
           "Alignment must be a power of two.");

    uintptr_t RequiredSize =
        Alignment * ((Size + Alignment - 1) / Alignment + 1);
    // FIXME! We may need to flush code cache when free space runs out.
    assert((CodeCache.CodeCachePtr + RequiredSize <
            CodeCache.CodeCacheBegin + CodeCache.CodeCacheSize) &&
           "CodeCache overflow.");

    uintptr_t Addr = (uintptr_t)CodeCache.CodeCachePtr;
    // Align the address.
    Addr = (Addr + Alignment - 1) & ~(uintptr_t)(Alignment - 1);

    // Adjust remaining free code cache.
    CodeCache.CodeCachePtr = (uint8_t *)(Addr + RequiredSize);

    return (uint8_t *)Addr;
}

uint8_t *COGBTMemoryManager::allocateDataSection(uintptr_t Size,
                                                 unsigned Alignment,
                                                 unsigned SectionID,
                                                 StringRef SectionName,
                                                 bool IsReadOnly) {
    return allocateCodeSection(Size, Alignment, SectionID, SectionName);
}

bool COGBTMemoryManager::finalizeMemory(std::string *ErrMsg) {
    // In cogbt, we don't have to set code cache permission as it has been set
    // already.
    return false;
}
