/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_LIVEPAYLOAD_PAYLOAD_H__
#define __XEN_LIVEPAYLOAD_PAYLOAD_H__

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */
typedef void livepatch_loadcall_t(void);
typedef void livepatch_unloadcall_t(void);

/*
 * LIVEPAYLOAD_LOAD_HOOK macro
 *
 * Declares a function pointer to be allocated in a new
 * .livepatch.hook.load section.  This livepatch_load_data symbol is later
 * stripped by create-diff-object so that it can be declared in multiple
 * objects that are later linked together, avoiding global symbol
 * collision.  Since multiple hooks can be registered, the
 * .livepatch.hook.load section is a table of functions that will be
 * executed in series by the livepatch infrastructure at patch load time.
 */
#define LIVEPAYLOAD_LOAD_HOOK(_fn) \
    livepatch_loadcall_t *__attribute__((weak)) \
        livepatch_load_data_##_fn __section(".livepatch.hooks.load") = _fn;

/*
 * LIVEPAYLOAD_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define LIVEPAYLOAD_UNLOAD_HOOK(_fn) \
    livepatch_unloadcall_t *__attribute__((weak)) \
        livepatch_unload_data_##_fn __section(".livepatch.hooks.unload") = _fn;

/*
 * livepatch shadow variables
 *
 * These functions can be used to add new "shadow" fields to existing data
 * structures.  For example, to allocate a "newpid" variable associated with an
 * instance of task_struct, and assign it a value of 1000:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = livepatch_shadow_alloc(tsk, "newpid", sizeof(int));
 * if (newpid)
 * 	*newpid = 1000;
 *
 * To retrieve a pointer to the variable:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = livepatch_shadow_get(tsk, "newpid");
 * if (newpid)
 * 	printk("task newpid = %d\n", *newpid); // prints "task newpid = 1000"
 *
 * To free it:
 *
 * livepatch_shadow_free(tsk, "newpid");
 */

void *livepatch_shadow_alloc(const void *obj, const char *var, size_t size);
void livepatch_shadow_free(const void *obj, const char *var);
void *livepatch_shadow_get(const void *obj, const char *var);

#endif /* __XEN_LIVEPAYLOAD_PAYLOAD_H__ */
