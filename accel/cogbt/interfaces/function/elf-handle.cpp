#include <elf.h>
#include "frontend.h"

/* lookup .symtab and .dynsym section */
static bool find_sym_table(Elf64_Shdr *shdr, int shnum, Elf64_Word type, 
        int *sym_idx, int *str_idx) {
    /* type can be SHT_SYMTAB or SHT_DYNSYM */
    for (int i = 0; i < shnum; ++i) {
        if (shdr[i].sh_type == type) {
            *sym_idx = i;
            *str_idx = shdr[i].sh_link;
            return true;
        }
    }
    return false;
}

void parse_elf_format(const char* exec_path, vector<std::shared_ptr<JsonFunc>> 
        &JsonFuncs) {
    Elf64_Ehdr *ehdr = NULL;
    int shnum;
    ssize_t shsz;
    Elf64_Shdr *shdr = NULL;
    ssize_t secsz;
    int sym_idx;
    int str_idx;
    Elf64_Sym *syms = NULL;
    char *strs = NULL;
    int nsyms;
    /* set<uint64_t> WeakSyms; */
    set<uint64_t> Visited; 

    int fd = open(exec_path, O_RDONLY, 0);
    if (fd < 0) {
        perror("open file failed\n");
        return;
    }

    /* 1. read ELF header */
    ehdr = (Elf64_Ehdr *)alloca(sizeof(Elf64_Ehdr));
    if (pread(fd, ehdr, sizeof(Elf64_Ehdr), 0) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "read elf header failed\n");
        goto give_up;
    }

    /* 2. check if is an ELF shared object or exec */
    // (ehdr->e_type == ET_DYN)
    if (!((memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) && 
                (ehdr->e_type == ET_EXEC))) {
        fprintf(stderr, "not a exec object\n");
        goto give_up;
    }

    /* 3. read section headers */
    shnum = ehdr->e_shnum;
    shsz = shnum * ehdr->e_shentsize;
    shdr = (Elf64_Shdr *)alloca(shsz);
    if (pread(fd, shdr, shsz, ehdr->e_shoff) != shsz) {
        fprintf(stderr, "read section headers failed\n");
        goto give_up;
    }

    /* 4. lookup .symtab and .dynsym section */
    if (!find_sym_table(shdr, shnum, SHT_SYMTAB, &sym_idx, &str_idx)) {
        fprintf(stderr, "find no symbol table\n");
        goto give_up;
    }
    if (find_sym_table(shdr, shnum, SHT_DYNSYM, &sym_idx, &str_idx)) {
        fprintf(stderr, "The programs dynamically linked are not supported.\n");
        goto give_up;
    }

    /* 4.1 read symbol string */
    secsz = shdr[str_idx].sh_size;
    strs = (char *)malloc(secsz);
    if (!strs || pread(fd, strs, secsz, shdr[str_idx].sh_offset) != secsz) {
        fprintf(stderr, "read .symstr section failed\n");
        goto give_up;
    }

    /* 4.2 read symbol table */
    secsz = shdr[sym_idx].sh_size;
    syms = (Elf64_Sym *)malloc(secsz);
    if (!syms || pread(fd, syms, secsz, shdr[sym_idx].sh_offset) != secsz) {
        fprintf(stderr, "read .symtab section failed\n");
        goto give_up;
    }

    if (secsz / sizeof(Elf64_Sym) > INT_MAX) {
        fprintf(stderr, "Implausibly large symbol table, give up\n");
        goto give_up;
    }

    /* 4.3 scan symbol table, collect functions */

    nsyms = secsz / sizeof(Elf64_Sym);
    for (int i = 0; i < nsyms; ++i) {
        if (syms[i].st_shndx == SHN_UNDEF
            || syms[i].st_shndx >= SHN_LORESERVE
            || ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC) {
            /* Throw away entries which we do not need.  */
            /* FIXME we ignore IFUNC, which seems merely used by glibc */
            continue;
        }
        if (ELF64_ST_BIND(syms[i].st_info) == STB_WEAK) {
            /* WeakSyms.insert(syms[i].st_value); */
            continue;
        }
        if (syms[i].st_size == 0)
            continue;
        /* if (WeakSyms.count(syms[i].st_value)) */
        /*     WeakSyms.erase(syms[i].st_value); */
        if (Visited.count(syms[i].st_value) != 0)
            continue;
        Visited.insert(syms[i].st_value);
        std::shared_ptr<JsonFunc> JF(new JsonFunc(string(strs + syms[i].st_name),
                    syms[i].st_value, syms[i].st_value + syms[i].st_size));
        JsonFuncs.push_back(JF); 
    }

    // TODO: 
    // Note: Weak symbol works, when LOCAL/GLOBAL symbol at the same address
    // does not exist.
    /* if (!WeakSyms.empty()) { */
    /*     assert(0); */
    /* } */

    /* printf("%ld\n", JsonFuncs.size()); */

give_up:
    free(strs);
    free(syms);
    close(fd);
}
