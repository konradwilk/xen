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
#define XSPLICE_PATCH_FUNC_INTERNAL_SIZE    64
#else
#define XSPLICE_PATCH_FUNC_INTERNAL_SIZE    52
#endif

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

/*
 * We use alternative and exception table code - which by default are __init
 * only, however we need them during runtime. These macros allows us to build
 * the image with these functions built-in. (See the #else below).
 */
#define __INITCONST
#define __INITDATA
#define __INIT

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
bool_t is_patch(const void *addr);
unsigned long xsplice_symbols_lookup_by_name(const char *symname);
int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len);

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

/*
 * If not compiling with xSplice certain functionality should stay as
 * __init.
 */
#define __INITCONST    __initconst
#define __INITDATA     __initdata
#define __INIT         __init

#include <xen/errno.h> /* For -ENOSYS */
static inline int xsplice_op(struct xen_sysctl_xsplice_op *op)
{
    return -ENOSYS;
}

static inline void check_for_xsplice_work(void) { };
static inline bool_t is_patch(const void *addr)
{
    return 0;
}
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
