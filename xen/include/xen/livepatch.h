/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_LIVE_PATCH_H__
#define __XEN_LIVE_PATCH_H__

struct livepatch_elf;
struct livepatch_elf_sec;
struct livepatch_elf_sym;
struct xen_sysctl_livepatch_op;

#include <xen/elfstructs.h>
#ifdef CONFIG_LIVE_PATCH

/*
 * We use alternative and exception table code - which by default are __init
 * only, however we need them during runtime. These macros allows us to build
 * the image with these functions built-in. (See the #else below).
 */
#define init_or_livepatch_const
#define init_or_livepatch_constrel
#define init_or_livepatch_data
#define init_or_livepatch

/* Convenience define for printk. */
#define LIVE_PATCH             "livepatch: "
/* ELF payload special section names. */
#define ELF_LIVE_PATCH_FUNC    ".livepatch.funcs"
#define ELF_LIVE_PATCH_DEPENDS ".livepatch.depends"
#define ELF_BUILD_ID_NOTE      ".note.gnu.build-id"

struct livepatch_symbol {
    const char *name;
    unsigned long value;
    unsigned int size;
    bool_t new_symbol;
};

int livepatch_op(struct xen_sysctl_livepatch_op *);
void check_for_livepatch_work(void);
unsigned long livepatch_symbols_lookup_by_name(const char *symname);
bool_t is_patch(const void *addr);
int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len);

/* Arch hooks. */
int arch_livepatch_verify_elf(const struct livepatch_elf *elf);
int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela);
int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela);
enum va_type {
    LIVE_PATCH_VA_RX, /* .text */
    LIVE_PATCH_VA_RW, /* .data */
    LIVE_PATCH_VA_RO, /* .rodata */
};

/*
 * Function to secure the allocate pages (from arch_livepatch_alloc_payload)
 * with the right page permissions.
 */
int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type types);

void arch_livepatch_init(void);

#include <public/sysctl.h> /* For struct livepatch_func. */
int arch_livepatch_verify_func(const struct livepatch_func *func);
/*
 * These functions are called around the critical region patching live code,
 * for an architecture to take make appropratie global state adjustments.
 */
void arch_livepatching_enter(void);
void arch_livepatching_leave(void);

void arch_livepatch_apply_jmp(struct livepatch_func *func);
void arch_livepatch_revert_jmp(const struct livepatch_func *func);
void arch_livepatch_post_action(void);

void arch_livepatch_mask(void);
void arch_livepatch_unmask(void);
#else

/*
 * If not compiling with live patching certain functionality should stay as
 * __init.
 */
#define init_or_livepatch_const       __initconst
#define init_or_livepatch_constrel    __initconstrel
#define init_or_livepatch_data        __initdata
#define init_or_livepatch             __init

#include <xen/errno.h> /* For -ENOSYS */
static inline int livepatch_op(struct xen_sysctl_livepatch_op *op)
{
    return -ENOSYS;
}

static inline void check_for_livepatch_work(void) { };
static inline bool_t is_patch(const void *addr)
{
    return 0;
}
#endif /* CONFIG_LIVE_PATCH */

#endif /* __XEN_LIVE_PATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
