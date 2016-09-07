/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#ifndef __XEN_ARM_LIVEPATCH_H__
#define __XEN_ARM_LIVEPATCH_H__

#include <xen/sizes.h> /* For SZ_* macros. */

/* On ARM32,64 instructions are always 4 bytes long. */
#define PATCH_INSN_SIZE 4

/*
 * The va of the hypervisor .text region. We need this as the
 * normal va are write protected.
 */
extern void *vmap_of_xen_text;

#ifdef CONFIG_ARM_32
#define LIVEPATCH_ARCH_RANGE SZ_32M
#else
#define LIVEPATCH_ARCH_RANGE SZ_128M
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
