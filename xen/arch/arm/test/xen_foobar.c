/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <public/sysctl.h>

static char foobar_patch_this_fnc[] = "xen_extra_version";

static char foobar_version[6];

noinline int foo(char *s)
{
    return snprintf(s, 3, "foo"); 
}

noinline int bar(char *s)
{
    return snprintf(s, 3, "bar");
}

const char* xen_foobar(void)
{
    char *s, *p;

    s = p = foobar_version;

    s += foo(s);
    s += bar(s);

    return p;
}

struct livepatch_func __section(".livepatch.funcs") livepatch_xen_foobar = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = foobar_patch_this_fnc,
    .new_addr = xen_foobar,
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
