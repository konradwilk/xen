/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_XSPLICE_PATCH_H__
#define __XEN_XSPLICE_PATCH_H__

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */
typedef void xsplice_loadcall_t(void);
typedef void xsplice_unloadcall_t(void);

/*
 * XSPLICE_LOAD_HOOK macro
 *
 * Declares a function pointer to be allocated in a new
 * .xsplice.hook.load section.  This xsplice_load_data symbol is later
 * stripped by create-diff-object so that it can be declared in multiple
 * objects that are later linked together, avoiding global symbol
 * collision.  Since multiple hooks can be registered, the
 * .xsplice.hook.load section is a table of functions that will be
 * executed in series by the xsplice infrastructure at patch load time.
 */
#define XSPLICE_LOAD_HOOK(_fn) \
    xsplice_loadcall_t *__attribute__((weak)) \
        xsplice_load_data_##_fn __section(".xsplice.hooks.load") = _fn;

/*
 * XSPLICE_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define XSPLICE_UNLOAD_HOOK(_fn) \
    xsplice_unloadcall_t *__attribute__((weak)) \
        xsplice_unload_data_##_fn __section(".xsplice.hooks.unload") = _fn;


/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */

/*
 * xsplice shadow variables
 *
 * These functions can be used to add new "shadow" fields to existing data
 * structures.  For example, to allocate a "newpid" variable associated with an
 * instance of task_struct, and assign it a value of 1000:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = xsplice_shadow_alloc(tsk, "newpid", sizeof(int));
 * if (newpid)
 * 	*newpid = 1000;
 *
 * To retrieve a pointer to the variable:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = xsplice_shadow_get(tsk, "newpid");
 * if (newpid)
 * 	printk("task newpid = %d\n", *newpid); // prints "task newpid = 1000"
 *
 * To free it:
 *
 * xsplice_shadow_free(tsk, "newpid");
 */

void *xsplice_shadow_alloc(const void *obj, const char *var, size_t size);
void xsplice_shadow_free(const void *obj, const char *var);
void *xsplice_shadow_get(const void *obj, const char *var);

#endif /* __XEN_XSPLICE_PATCH_H__ */
