/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/types.h>
#include <asm/nops.h>
#include <asm/alternative.h>

/* Our replacement function for xen_hello_world. */
const char *xen_replace_world(void)
{
    return "Hello Again World!";
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
