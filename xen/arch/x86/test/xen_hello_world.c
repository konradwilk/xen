/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/types.h>
#include <xen/version.h>
#include <xen/xhot_patch.h>

#include <public/sysctl.h>

static char hello_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_hello_world(void);

struct xhot_patch_patch_func __section(".xhot_patch.funcs") xhot_patch_xen_hello_world = {
    .version = XHOT_PATCH_PAYLOAD_VERSION,
    .name = hello_world_patch_this_fnc,
    .new_addr = xen_hello_world,
    .old_addr = xen_extra_version,
    .new_size = NEW_CODE_SZ,
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
