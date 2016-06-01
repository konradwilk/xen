/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_LIVE_PATCH_ELF_H__
#define __XEN_LIVE_PATCH_ELF_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

/* The following describes an Elf file as consumed by Xen Live Patching. */
struct live_patch_elf_sec {
    const Elf_Shdr *sec;                 /* Hooked up in elf_resolve_sections.*/
    const char *name;                    /* Human readable name hooked in
                                            elf_resolve_section_names. */
    const void *data;                    /* Pointer to the section (done by
                                            elf_resolve_sections). */
    void *load_addr;                     /* A pointer to the allocated destination.
                                            Done by load_payload_data. */
};

struct live_patch_elf_sym {
    const Elf_Sym *sym;
    const char *name;
};

struct live_patch_elf {
    const char *name;                    /* Pointer to payload->name. */
    size_t len;                          /* Length of the ELF file. */
    const Elf_Ehdr *hdr;                 /* ELF file. */
    struct live_patch_elf_sec *sec;      /* Array of sections, allocated by us. */
    struct live_patch_elf_sym *sym;      /* Array of symbols , allocated by us. */
    unsigned int nsym;
    const struct live_patch_elf_sec *symtab;/* Pointer to .symtab section - aka to
                                            sec[symtab_idx]. */
    const struct live_patch_elf_sec *strtab;/* Pointer to .strtab section. */
    unsigned int symtab_idx;
};

const struct live_patch_elf_sec *
live_patch_elf_sec_by_name(const struct live_patch_elf *elf,
                           const char *name);
int live_patch_elf_load(struct live_patch_elf *elf, const void *data);
void live_patch_elf_free(struct live_patch_elf *elf);

int live_patch_elf_resolve_symbols(struct live_patch_elf *elf);
int live_patch_elf_perform_relocs(struct live_patch_elf *elf);

#endif /* __XEN_LIVE_PATCH_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
