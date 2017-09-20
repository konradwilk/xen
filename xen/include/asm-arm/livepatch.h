/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_ARM_LIVEPATCH_H__
#define __XEN_ARM_LIVEPATCH_H__

#include <xen/sizes.h> /* For SZ_* macros. */

/* On ARM32,64 instructions are always 4 bytes long. */
#define ARCH_PATCH_INSN_SIZE 4

/*
 * The va of the hypervisor .text region. We need this as the
 * normal va are write protected.
 */
extern void *vmap_of_xen_text;

/*
 * The va of the livepatch .livepatch.funcs. Only used if said
 * region is in RO VA and we need to modify it to RW during
 * livepatching.
 */
struct livepatch_va
{
    unsigned long va;
    unsigned int pages;
};

extern struct livepatch_va livepatch_stash;

/* These ranges are only for unconditional branches. */
#ifdef CONFIG_ARM_32
/* ARM32: A4.3 IN ARM DDI 0406C.c -  we are using only ARM instructions in Xen.*/
#define ARCH_LIVEPATCH_RANGE SZ_32M
#else
/* ARM64: C1.3.2 in ARM DDI 0487A.j */
#define ARCH_LIVEPATCH_RANGE SZ_128M
#endif

#endif /* __XEN_ARM_LIVEPATCH_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
