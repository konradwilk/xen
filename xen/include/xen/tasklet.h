/******************************************************************************
 * tasklet.h
 * 
 * Tasklets are dynamically-allocatable tasks run in either VCPU context
 * (specifically, the idle VCPU's context) or in softirq context, on at most
 * one CPU at a time. Softirq versus VCPU context execution is specified
 * during per-tasklet initialisation.
 */

#ifndef __XEN_TASKLET_H__
#define __XEN_TASKLET_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/percpu.h>

struct tasklet
{
    struct list_head list;
    unsigned long state;
    int scheduled_on;
    bool_t is_softirq;
    bool_t is_running;
    bool_t is_dead;
    bool_t is_percpu;
    void (*func)(unsigned long);
    unsigned long data;
};

#define _DECLARE_TASKLET(name, func, data, softirq, percpu)             \
    struct tasklet name = {                                             \
        LIST_HEAD_INIT(name.list), 0, -1, softirq, 0, 0, percpu,        \
        func, data }
#define DECLARE_TASKLET(name, func, data)               \
    _DECLARE_TASKLET(name, func, data, 0, 0)
#define DECLARE_SOFTIRQ_TASKLET(name, func, data)       \
    _DECLARE_TASKLET(name, func, data, 1, 0)

/* Indicates status of tasklet work on each CPU. */
DECLARE_PER_CPU(unsigned long, tasklet_work_to_do);
#define _TASKLET_enqueued  0 /* Tasklet work is enqueued for this CPU. */
#define _TASKLET_scheduled 1 /* Scheduler has scheduled do_tasklet(). */
#define TASKLET_enqueued   (1ul << _TASKLET_enqueued)
#define TASKLET_scheduled  (1ul << _TASKLET_scheduled)

/* These fancy bit manipulations (bit 0 and bit 1) along with using a lock
 * operation allow us to have four stages in tasklet life-time.
 *  a) 0x0: Completely empty (not scheduled nor running).
 *  b) 0x1: Scheduled but not running. Used to guard in 'tasklet_schedule'
 *     such that we will only schedule one. If it is scheduled and had never
 *     run (hence never clearing STATE_SCHED bit), tasklet_kill will spin
 *     forever on said tasklet. However 'tasklet_schedule' raises the
 *     softirq associated with the per-cpu - so it will run, albeit there might
 *     be a race (tasklet_kill spinning until the softirq handler runs).
 *  c) 0x2: it is running (only on one CPU) and can be scheduled on any
 *     CPU. The bit 0 - scheduled is cleared at this stage allowing
 *     'tasklet_schedule' to succesfully schedule.
 *  d) 0x3: scheduled and running - only possible if the running tasklet calls
 *     tasklet_schedule (on same CPU) or the tasklet is scheduled from another
 *     CPU while the tasklet is running on another CPU.
 *
 * The two bits play a vital role in assuring that the tasklet is scheduled
 * once and runs only once. The steps are:
 *
 *  1) tasklet_schedule: STATE_SCHED bit set (0x1), added on the per cpu list.
 *  2) tasklet_softirq_percpu_action picks one tasklet from the list. Schedules
 *  itself later if there are more tasklets on it. Tries to set STATE_RUN bit
 *  (0x3) - if it fails adds tasklet back to the per-cpu list. If it succeeds
 *  clears the STATE_SCHED bit (0x2). Once tasklet completed, unsets STATE_RUN
 *  (0x0 or 0x1 if tasklet called tasklet_schedule).
 */
enum {
    TASKLET_STATE_SCHED, /* Bit 0 */
    TASKLET_STATE_RUN
};

static inline int tasklet_trylock(struct tasklet *t)
{
    return !test_and_set_bit(TASKLET_STATE_RUN, &(t)->state);
}

static inline void tasklet_unlock(struct tasklet *t)
{
    barrier();
    clear_bit(TASKLET_STATE_RUN, &(t)->state);
}
static inline void tasklet_unlock_wait(struct tasklet *t)
{
    while (test_bit(TASKLET_STATE_RUN, &(t)->state))
    {
        barrier();
    }
}
void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu);
void tasklet_schedule(struct tasklet *t);
void do_tasklet(void);
void tasklet_kill(struct tasklet *t);
void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void softirq_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void percpu_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void tasklet_subsys_init(void);

#endif /* __XEN_TASKLET_H__ */
