/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_XHOT_PATCH_H__
#define __XEN_XHOT_PATCH_H__

struct xhot_patch_elf;
struct xhot_patch_elf_sec;
struct xhot_patch_elf_sym;
struct xen_sysctl_xhot_patch_op;

#include <xen/elfstructs.h>
#ifdef CONFIG_XHOT_PATCH

/*
 * We use alternative and exception table code - which by default are __init
 * only, however we need them during runtime. These macros allows us to build
 * the image with these functions built-in. (See the #else below).
 */
#define init_or_xhot_patch_const
#define init_or_xhot_patch_constrel
#define init_or_xhot_patch_data
#define init_or_xhot_patch

/* Convenience define for printk. */
#define XHOT_PATCH             "xhot_patch: "
/* ELF payload special section names. */
#define ELF_XHOT_PATCH_FUNC    ".xhot_patch.funcs"
#define ELF_XHOT_PATCH_DEPENDS ".xhot_patch.depends"
#define ELF_BUILD_ID_NOTE      ".note.gnu.build-id"

struct xhot_patch_symbol {
    const char *name;
    unsigned long value;
    unsigned int size;
    bool_t new_symbol;
};

int xhot_patch_op(struct xen_sysctl_xhot_patch_op *);
void check_for_xhot_patch_work(void);
unsigned long xhot_patch_symbols_lookup_by_name(const char *symname);
bool_t is_patch(const void *addr);
int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len);

/* Arch hooks. */
int arch_xhot_patch_verify_elf(const struct xhot_patch_elf *elf);
int arch_xhot_patch_perform_rel(struct xhot_patch_elf *elf,
                                const struct xhot_patch_elf_sec *base,
                                const struct xhot_patch_elf_sec *rela);
int arch_xhot_patch_perform_rela(struct xhot_patch_elf *elf,
                                 const struct xhot_patch_elf_sec *base,
                                 const struct xhot_patch_elf_sec *rela);
enum va_type {
    XHOT_PATCH_VA_RX, /* .text */
    XHOT_PATCH_VA_RW, /* .data */
    XHOT_PATCH_VA_RO, /* .rodata */
};

/*
 * Function to secure the allocate pages (from arch_xhot_patch_alloc_payload)
 * with the right page permissions.
 */
int arch_xhot_patch_secure(const void *va, unsigned int pages, enum va_type types);

void arch_xhot_patch_init(void);

#include <public/sysctl.h> /* For struct xhot_patch_patch_func. */
int arch_xhot_patch_verify_func(const struct xhot_patch_patch_func *func);
/*
 * These functions are called around the critical region patching live code,
 * for an architecture to take make appropratie global state adjustments.
 */
void arch_xhot_patch_patching_enter(void);
void arch_xhot_patch_patching_leave(void);

void arch_xhot_patch_apply_jmp(struct xhot_patch_patch_func *func);
void arch_xhot_patch_revert_jmp(const struct xhot_patch_patch_func *func);
void arch_xhot_patch_post_action(void);

void arch_xhot_patch_mask(void);
void arch_xhot_patch_unmask(void);
#else

/*
 * If not compiling with xHot Patch certain functionality should stay as
 * __init.
 */
#define init_or_xhot_patch_const       __initconst
#define init_or_xhot_patch_constrel    __initconstrel
#define init_or_xhot_patch_data        __initdata
#define init_or_xhot_patch             __init

#include <xen/errno.h> /* For -ENOSYS */
static inline int xhot_patch_op(struct xen_sysctl_xhot_patch_op *op)
{
    return -ENOSYS;
}

static inline void check_for_xhot_patch_work(void) { };
static inline bool_t is_patch(const void *addr)
{
    return 0;
}
#endif /* CONFIG_XHOT_PATCH */

#endif /* __XEN_XHOT_PATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
