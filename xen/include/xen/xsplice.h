/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_XSPLICE_H__
#define __XEN_XSPLICE_H__

struct xsplice_elf;
struct xsplice_elf_sec;
struct xsplice_elf_sym;
struct xen_sysctl_xsplice_op;

#include <xen/elfstructs.h>
#ifdef CONFIG_XSPLICE

/*
 * The structure which defines the patching. This is what the hypervisor
 * expects in the '.xsplice.func' section of the ELF file.
 *
 * This MUST be in sync with what the tools generate. We expose
 * for the tools the 'struct xsplice_patch_func' which does not have
 * platform specific entries.
 */
#if BITS_PER_LONG == 64
struct xsplice_patch_func_internal {
    const char *name;
    void *new_addr;
    void *old_addr;
    uint32_t new_size;
    uint32_t old_size;
    uint8_t version;
    union {
#ifndef CONFIG_ARM
        uint8_t undo[8];
#endif
        uint8_t pad[31];
    } u;
};
#else
struct xsplice_patch_func_internal {
    const char *name;
    uint32_t _pad0;
    void *new_addr;
    uint32_t _pad1;
    void *old_addr;
    uint32_t _pad2;
    uint32_t new_size;
    uint32_t old_size;
    uint8_t version;
    union {
        uint8_t pad[31];
    } u;
};
#endif

/* Convenience define for printk. */
#define XSPLICE "xsplice: "

struct xsplice_symbol {
    const char *name;
    uint64_t value;
    size_t size;
    bool_t new_symbol;
};

int xsplice_op(struct xen_sysctl_xsplice_op *);
void check_for_xsplice_work(void);
unsigned long xsplice_symbols_lookup_by_name(const char *symname);

/* Arch hooks. */
int arch_xsplice_verify_elf(const struct xsplice_elf *elf);
int arch_xsplice_perform_rel(struct xsplice_elf *elf,
                             const struct xsplice_elf_sec *base,
                             const struct xsplice_elf_sec *rela);
int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela);
enum va_type {
    XSPLICE_VA_RX, /* .text */
    XSPLICE_VA_RW, /* .data */
    XSPLICE_VA_RO, /* .rodata */
};

#include <xen/mm.h>
void *arch_xsplice_alloc_payload(unsigned int pages);

/*
 * Function to secure the allocate pages (from arch_xsplice_alloc_payload)
 * with the right page permissions.
 */
int arch_xsplice_secure(void *va, unsigned int pages, enum va_type types);

void arch_xsplice_free_payload(void *va);

void arch_xsplice_init(void);

int arch_xsplice_verify_func(const struct xsplice_patch_func_internal *func);
/*
 * These functions are called around the critical region patching live code,
 * for an architecture to take make appropratie global state adjustments.
 */
void arch_xsplice_patching_enter(void);
void arch_xsplice_patching_leave(void);

void arch_xsplice_apply_jmp(struct xsplice_patch_func_internal *func);
void arch_xsplice_revert_jmp(const struct xsplice_patch_func_internal *func);
void arch_xsplice_post_action(void);

void arch_xsplice_mask(void);
void arch_xsplice_unmask(void);
#else

#include <xen/errno.h> /* For -ENOSYS */
static inline int xsplice_op(struct xen_sysctl_xsplice_op *op)
{
    return -ENOSYS;
}

static inline void check_for_xsplice_work(void) { };
#endif /* CONFIG_XSPLICE */

#endif /* __XEN_XSPLICE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
