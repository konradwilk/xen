/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/types.h>

#include <public/sysctl.h>

/*
 * All of the .new_size and .old_addr are based on assumptions that the
 * code for 'xen_minor_version' is compiled in specific way. Before
 * running this test-case you MUST verify that the assumptions are
 * correct (Hint: make debug and look in xen.s).
 */
struct livepatch_func __section(".livepatch.funcs") livepatch_nop = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .old_size = MINOR_VERSION_SZ,

#ifdef CONFIG_X86
    .old_addr = (void *)MINOR_VERSION_ADDR,
    /* Everything but the last instruction: "req". */
    .new_size = MINOR_VERSION_SZ-1,
#endif

#ifdef CONFIG_ARM_64
    .old_addr = (void *)MINOR_VERSION_ADDR,
    /* Replace the first one: "mov w0, #0x8".  */
    .new_size = 4,
#endif

#ifdef CONFIG_ARM_32
    /* Skip the first instruction: "push {fp}". */
    .old_addr = (void *)(MINOR_VERSION_ADDR + 4),
    /* And replace the next three instructions. */
    .new_size = 3 * 4,
#endif
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
