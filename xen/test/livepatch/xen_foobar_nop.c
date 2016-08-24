/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config-reloc.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <public/sysctl.h>

static char foobar_nop_patch_this_fnc[] = "xen_extra_version+"BAR_OFFSET;

struct livepatch_func __section(".livepatch.funcs") livepatch_xen_foobar_nop = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = foobar_nop_patch_this_fnc,
    .new_addr = 0, /* As we are NOP. */
    .old_addr = 0, /* Will lookup 'xen_extra_versionr+0x5a' */
#ifdef CONFIG_X86_64
    .new_size = 5, /* As it is a NOP. */
#else
    .new_size = 4,
#endif
    .old_size = OLD_CODE_SZ,
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
