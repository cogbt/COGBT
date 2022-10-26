#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include "llvm/ExecutionEngine/RTDyldMemoryManager.h"
#include "llvm-translator.h"

/// This is a simple memory manager which implements the methods called by
/// the RuntimeDyld class to ALLOCATE MEMORY for section-based loading of
/// objects, usually those generated by the MCJIT execution engine.
///
/// This memory manager uses all preallocated memory with read-write-execution
/// permission.  The RuntimeDyld will copy JITed section memory into these code
/// cache and perform any necessary linking and relocations.
///
/// Any client using this memory manager MUST ensure that this allocable memory
/// region has already been set READ|WRITE|EXE permissions before attempting to
/// allocate code section or execute functions in the JITed object.
class COGBTMemoryManager final : public RTDyldMemoryManager {
public:
    /// Creates a COGBTMemoryManager instance with \p GlobalCodeCache as the
    /// associated allocable memory region info.
    COGBTMemoryManager(LLVMTranslator::CodeCacheInfo &GlobalCodeCache)
        : CodeCache(GlobalCodeCache) {}
    COGBTMemoryManager(const COGBTMemoryManager &) = delete;
    void operator=(const COGBTMemoryManager &) = delete;
    ~COGBTMemoryManager() override {}

    /// Allocates a memory block of (at least) the given size suitable for
    /// executable code.
    ///
    /// The value of \p Alignment must be a power of two.  If \p Alignment is
    /// zero a default alignment of 16 will be used.
    uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                                 unsigned SectionID,
                                 StringRef SectionName) override;

    /// Allocates a memory block of (at least) the given size suitable for
    /// executable code.
    ///
    /// The value of \p Alignment must be a power of two.  If \p Alignment is
    /// zero a default alignment of 16 will be used.
    uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                                 unsigned SectionID, StringRef SectionName,
                                 bool isReadOnly) override;

    /// Update section-specific memory permissions and other attributes.
    ///
    /// This method is called when object loading is complete and section page
    /// permissions can be applied.  It is up to the memory manager
    /// implementation to decide whether or not to act on this method.  The
    /// memory manager will typically allocate all sections as read-write and
    /// then apply specific permissions when this method is called.  Code
    /// sections cannot be executed until this function has been called.  In
    /// addition, any cache coherency operations needed to reliably use the
    /// memory are also performed.
    ///
    /// \returns true if an error occurred, false otherwise.
    bool finalizeMemory(std::string *ErrMsg = nullptr) override;


    /* void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr, size_t Size) override { */
    /*     dbgs() << "Debug registerEHFrames\n"; // debug */
    /* } */
    /* void deregisterEHFrames() override { */
    /*     dbgs() << "Debug deregisterEHFrames\n"; //debug */
    /* } */

private:
    LLVMTranslator::CodeCacheInfo &CodeCache;
};

#endif // LLVM_EXECUTIONENGINE_COGBTMemoryManager_H
