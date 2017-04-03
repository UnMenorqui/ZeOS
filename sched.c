/*
 * sched.c - initializes struct for task 0 anda task 1
 */

#include <types.h>
#include <hardware.h>
#include <segment.h>
#include <sched.h>
#include <mm.h>
#include <io.h>
#include <utils.h>
#include <update_stats.h>


/**
 * Container for the Task array and 2 additional pages (the first and the last one)
 * to protect against out of bound accesses.
 */
union task_union protected_tasks[NR_TASKS+2]
  __attribute__((__section__(".data.task")));

union task_union *task = &protected_tasks[1]; /* == union task_union task[NR_TASKS] */
struct task_struct *idle_task = NULL;


struct task_struct *list_head_to_task_struct(struct list_head *l)
{
	return (struct task_struct*)((unsigned int) l&0xfffff000);
 }


extern struct list_head blocked;

struct list_head freequeue;
struct list_head readyqueue;

void init_stats (struct stats *s) 
{
	s->user_ticks = 0;
	s->system_ticks = 0;
	s->blocked_ticks = 0;
	s->ready_ticks = 0;
	s->elapsed_total_ticks = get_ticks();
	s->total_trans = 0;
	s->remaining_ticks = get_ticks();
}


/* get_DIR - Returns the Page Directory address for task 't' */
page_table_entry * get_DIR (struct task_struct *t) 
{
	return t->dir_pages_baseAddr;
}

/* get_PT - Returns the Page Table address for task 't' */
page_table_entry * get_PT (struct task_struct *t) 
{
	return (page_table_entry *)(((unsigned int)(t->dir_pages_baseAddr->bits.pbase_addr))<<12);
}


int allocate_DIR(struct task_struct *t) 
{
	int pos;

	pos = ((int)t-(int)task)/sizeof(union task_union);

	t->dir_pages_baseAddr = (page_table_entry*) &dir_pages[pos]; 

	return 1;
}

void cpu_idle(void)
{
	__asm__ __volatile__("sti": : :"memory");

	while(1)
	{
	;
	}
}

void init_idle (void)
{
	union task_union *pointer = (union task_union*) list_head_to_task_struct(list_first(&freequeue));
	list_del(list_first(&freequeue));
	pointer->task.PID = 0;
	allocate_DIR(&pointer->task); //nunca falla 
	pointer->stack[1023] = (unsigned int) &cpu_idle;
	pointer->stack[1022] = 0;
	pointer->task.register_esp = (unsigned long) &pointer->stack[1022];
	idle_task = &pointer->task;  //idle_task apunta al task struct del idle proces
}

void init_task1(void)
{
	union task_union *pointer = (union task_union*) list_head_to_task_struct(list_first(&freequeue));
	list_del(list_first(&freequeue));
	pointer->task.PID = 1;
	allocate_DIR(&pointer->task);
	set_user_pages(&pointer->task);
	tss.esp0 = (unsigned long) &pointer->stack[KERNEL_STACK_SIZE];
	set_cr3(pointer->task.dir_pages_baseAddr);
}


void init_sched()
{
	INIT_LIST_HEAD( &readyqueue);
	INIT_LIST_HEAD( &freequeue);
	int i;
	for (i = 0; i < 10; i++) list_add(&task[i].task.list, &freequeue);
}

void inner_task_switch(union task_union *new) {
	page_table_entry *new_DIR = get_DIR(&new->task);
	tss.esp0 = (unsigned long) &(new->stack[1024]);
	set_cr3(new_DIR);
	
	__asm__ __volatile__(
		"movl %%ebp, %0"
		: "=g" (current()->register_esp)
	);

	__asm__ __volatile__(
		"movl %0, %%esp"
		:
		: "g" (new->task.register_esp)
	);
	
	__asm__ __volatile__(
		"popl %ebp\n\t"
		"ret"
	);
}

void task_switch(union task_union *new) {
	__asm__ __volatile__ (
		"pushl %ebx\n\t"
		"pushl %edi\n\t"
		"pushl %esi"
	);
	inner_task_switch(new);
	__asm__ __volatile__ (
		"popl %esi\n\t"
		"popl %edi\n\t"
		"popl %ebx"
	);

}


#define DEFAULT_QUANTUM 10
int remaining_quantum = 0;

void update_sched_data_rr (void) {
	remaining_quantum--;
}


int get_quantum (struct task_struct *t) {
	return t->total_quantum;
}

void set_quantum (struct task_struct *t, int new_quantum) {
	t->total_quantum = new_quantum;
}

int needs_sched_rr (void) {
	if (remaining_quantum == 0) {
            //si la llista de ready esta buida, tornem a assignar quantum 
		if (!list_empty(&readyqueue)) return 1;
		remaining_quantum = get_quantum(current());
	}
	return 0;
}

void update_process_state_rr(struct task_struct *t, struct list_head *dst_queue)
{
	if (t->state!=ST_RUN) list_del(&(t->list));
	if (dst_queue!=NULL) {
		list_add_tail(&(t->list), dst_queue);
		if (dst_queue!=&readyqueue) t->state = ST_BLOCKED;
		else {
                        update_stats(&(t->p_stats.system_ticks), &(t->p_stats.elapsed_total_ticks));
			t->state = ST_READY;
		}
	}
	else {
		t->state = ST_RUN;
	}
}

void sched_next_rr(void)
{
  struct task_struct *ts;

  if (!list_empty(&readyqueue)) {
	ts = list_head_to_task_struct(list_first(&readyqueue));
        list_del(list_first(&readyqueue));
  }
  else
    ts=idle_task;

  ts->state=ST_RUN;
  remaining_quantum=get_quantum(ts);
  
  update_stats(&(current()->p_stats.system_ticks), &(current()->p_stats.elapsed_total_ticks));
  update_stats(&(ts->p_stats.ready_ticks), &(ts->p_stats.elapsed_total_ticks));

  ts->p_stats.total_trans++;

  task_switch((union task_union*)ts);
}

void schedule()
{
  update_sched_data_rr();
  if (needs_sched_rr())
  {
    update_process_state_rr(current(), &readyqueue);
    sched_next_rr();
  }
}




struct task_struct* current()
{
  int ret_value;
  
  __asm__ __volatile__(
  	"movl %%esp, %0"
	: "=g" (ret_value)
  );
  return (struct task_struct*)(ret_value&0xfffff000);
}

