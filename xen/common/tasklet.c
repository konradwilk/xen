/******************************************************************************
 * tasklet.c
 * 
 * Tasklets are dynamically-allocatable tasks run in either VCPU context
 * (specifically, the idle VCPU's context) or in softirq context, on at most
 * one CPU at a time. Softirq versus VCPU context execution is specified
 * during per-tasklet initialisation.
 * 
 * Copyright (c) 2010, Citrix Systems, Inc.
 * Copyright (c) 1992, Linus Torvalds
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/cpu.h>

/* Some subsystems call into us before we are initialised. We ignore them. */
static bool_t tasklets_initialised;

DEFINE_PER_CPU(unsigned long, tasklet_work_to_do);

/* Protects the tasklet_feeder list. */
static DEFINE_SPINLOCK(feeder_lock);

static DEFINE_PER_CPU(struct list_head, tasklet_list);
static DEFINE_PER_CPU(struct list_head, softirq_list);
static DEFINE_PER_CPU(struct list_head, tasklet_feeder);

static void percpu_tasklet_feed(void *arg)
{
    unsigned long flags;
    struct tasklet *t;
    struct list_head *dst_list;
    struct list_head *list = &__get_cpu_var(tasklet_feeder);
    unsigned long *work_to_do = &__get_cpu_var(tasklet_work_to_do);
    bool_t poke = 0;

    spin_lock_irqsave(&feeder_lock, flags);

    if ( list_empty(list) )
        goto out;

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        list_del(&t->list);

        if ( t->is_softirq )
        {
            dst_list = &__get_cpu_var(softirq_list);
            poke = 1;
        }
        else
            dst_list = &__get_cpu_var(tasklet_list);

        list_add_tail(&t->list, dst_list);
    }
    if ( poke )
        raise_softirq(TASKLET_SOFTIRQ);
    else
    {
        if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
            raise_softirq(SCHEDULE_SOFTIRQ);
    }
out:
    spin_unlock_irqrestore(&feeder_lock, flags);
}

static void tasklet_enqueue(struct tasklet *t)
{
    unsigned int cpu = t->scheduled_on;
    unsigned long flags;
    struct list_head *list;

    INIT_LIST_HEAD(&t->list);

    if ( cpu != smp_processor_id() )
    {
        spin_lock_irqsave(&feeder_lock, flags);

        list = &per_cpu(tasklet_feeder, cpu);
        list_add_tail(&t->list, list);

        spin_unlock_irqrestore(&feeder_lock, flags);
        on_selected_cpus(cpumask_of(cpu), percpu_tasklet_feed, NULL, 1);
        return;
     }
     if ( t->is_softirq )
     {
         local_irq_save(flags);

         list = &__get_cpu_var(softirq_list);
         list_add_tail(&t->list, list);
         raise_softirq(TASKLET_SOFTIRQ);

         local_irq_restore(flags);
     }
     else
     {
          unsigned long *work_to_do = &__get_cpu_var(tasklet_work_to_do);

          local_irq_save(flags);

          list = &__get_cpu_var(tasklet_list);
          list_add_tail(&t->list, list);
          if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
            raise_softirq(SCHEDULE_SOFTIRQ);

          local_irq_restore(flags);
    }
}

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu)
{
    if ( !tasklets_initialised || t->is_dead )
        return;

    if ( !test_and_set_bit(TASKLET_STATE_SCHED, &t->state) )
    {
        t->scheduled_on = cpu;
        tasklet_enqueue(t);
    }
}

void tasklet_schedule(struct tasklet *t)
{
    tasklet_schedule_on_cpu(t, smp_processor_id());
}

/* Return 0 if there is more work to be done. */
static int do_tasklet_work(void)
{
    struct tasklet *t = NULL;
    struct list_head *head;
    int rc = 1; /* All done. */

    local_irq_disable();
    head = &__get_cpu_var(tasklet_list);

    if ( !list_empty(head) )
    {
        t = list_entry(head->next, struct tasklet, list);

        if ( head->next == head->prev ) /* One singular item. Re-init head. */
            INIT_LIST_HEAD(&__get_cpu_var(tasklet_list));
        else
        {
            /* Multiple items, update head to skip 't'. */
            struct list_head *list;

            /* One item past 't'. */
            list = head->next->next;

            BUG_ON(list == NULL);

            /* And update head to skip 't'. Note that t->list.prev still
             * points to head, but we don't care as we only process one tasklet
             * and once done the tasklet list is re-init one way or another.
             */
            head->next = list;
            rc = 0; /* More work to be done. */
        }
    }
    local_irq_enable();

    if ( !t )
        return 1; /* Never saw it happend, but we might have a spurious case? */

    if ( tasklet_trylock(t) )
    {
        if ( !test_and_clear_bit(TASKLET_STATE_SCHED, &t->state) )
                BUG();
        sync_local_execstate();
        t->func(t->data);
        tasklet_unlock(t);
        if ( rc == 0 )
            raise_softirq(TASKLET_SOFTIRQ);
        /* We could reinit the t->list but tasklet_enqueue does it for us. */
        return rc;
    }

    local_irq_disable();

    INIT_LIST_HEAD(&t->list);
    list_add_tail(&t->list, &__get_cpu_var(tasklet_list));
    smp_wmb();
    raise_softirq(TASKLET_SOFTIRQ);
    local_irq_enable();

    return 0; /* More to do. */
}

void do_tasklet_work_percpu(void)
{
    struct tasklet *t = NULL;
    struct list_head *head;
    bool_t poke = 0;

    local_irq_disable();
    head = &__get_cpu_var(softirq_list);

    if ( !list_empty(head) )
    {
        t = list_entry(head->next, struct tasklet, list);

        if ( head->next == head->prev ) /* One singular item. Re-init head. */
            INIT_LIST_HEAD(&__get_cpu_var(softirq_list));
        else
        {
            /* Multiple items, update head to skip 't'. */
            struct list_head *list;

            /* One item past 't'. */
            list = head->next->next;

            BUG_ON(list == NULL);

            /* And update head to skip 't'. Note that t->list.prev still
             * points to head, but we don't care as we only process one tasklet
             * and once done the tasklet list is re-init one way or another.
             */
            head->next = list;
            poke = 1;
        }
    }
    local_irq_enable();

    if ( !t )
        return; /* Never saw it happend, but we might have a spurious case? */

    if ( tasklet_trylock(t) )
    {
        if ( !test_and_clear_bit(TASKLET_STATE_SCHED, &t->state) )
                BUG();
        sync_local_execstate();
        t->func(t->data);
        tasklet_unlock(t);
        if ( poke )
            raise_softirq(TASKLET_SOFTIRQ);
        /* We could reinit the t->list but tasklet_enqueue does it for us. */
        return;
    }

    local_irq_disable();

    INIT_LIST_HEAD(&t->list);
    list_add_tail(&t->list, &__get_cpu_var(softirq_list));
    smp_wmb();
    raise_softirq(TASKLET_SOFTIRQ);
    local_irq_enable();
}

/* VCPU context work */
void do_tasklet(void)
{
    unsigned int cpu = smp_processor_id();
    unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);

    /*
     * Work must be enqueued *and* scheduled. Otherwise there is no work to
     * do, and/or scheduler needs to run to update idle vcpu priority.
     */
    if ( likely(*work_to_do != (TASKLET_enqueued|TASKLET_scheduled)) )
        return;

    if ( do_tasklet_work() )
    {
        clear_bit(_TASKLET_enqueued, work_to_do);
        raise_softirq(SCHEDULE_SOFTIRQ);
    }
}


/* Per CPU softirq context work. */
static void tasklet_softirq_action(void)
{
    do_tasklet_work_percpu();
}

void tasklet_kill(struct tasklet *t)
{
    while ( test_and_set_bit(TASKLET_STATE_SCHED, &t->state) )
    {
        do {
                process_pending_softirqs();
        } while ( test_bit(TASKLET_STATE_SCHED, &t->state) );
    }
    tasklet_unlock_wait(t);
    clear_bit(TASKLET_STATE_SCHED, &t->state);
    t->is_dead = 1;
}

static void migrate_tasklets_from_cpu(unsigned int cpu, struct list_head *list)
{
    unsigned long flags;
    struct tasklet *t;

    spin_lock_irqsave(&feeder_lock, flags);

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        BUG_ON(t->scheduled_on != cpu);
        t->scheduled_on = smp_processor_id();
        list_del(&t->list);
        tasklet_enqueue(t);
    }

    spin_unlock_irqrestore(&feeder_lock, flags);
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    INIT_LIST_HEAD(&t->list);
    t->scheduled_on = -1;
    t->func = func;
    t->data = data;
}

void softirq_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    tasklet_init(t, func, data);
    t->is_softirq = 1;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    unsigned long *work_to_do;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        INIT_LIST_HEAD(&per_cpu(softirq_list, cpu));
        INIT_LIST_HEAD(&per_cpu(tasklet_feeder, cpu));
        INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        migrate_tasklets_from_cpu(cpu, &per_cpu(softirq_list, cpu));
        migrate_tasklets_from_cpu(cpu, &per_cpu(tasklet_feeder, cpu));
        migrate_tasklets_from_cpu(cpu, &per_cpu(tasklet_list, cpu));

        work_to_do = &per_cpu(tasklet_work_to_do, cpu);
        if ( test_bit(_TASKLET_enqueued, work_to_do) )
        {
            work_to_do = &__get_cpu_var(tasklet_work_to_do);
            if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
                raise_softirq(SCHEDULE_SOFTIRQ);
        }
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    .priority = 99
};

void __init tasklet_subsys_init(void)
{
    void *hcpu = (void *)(long)smp_processor_id();
    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    register_cpu_notifier(&cpu_nfb);
    open_softirq(TASKLET_SOFTIRQ, tasklet_softirq_action);
    tasklets_initialised = 1;
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
