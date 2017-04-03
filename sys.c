/*
 * sys.c - Syscalls implementation
 */
#include <devices.h>
#include <utils.h>
#include <io.h>
#include <mm.h>
#include <mm_address.h>
#include <sched.h>
#include <errno.h>
#include <libc.h>
#include <types.h>


#define LECTURA 0
#define ESCRIPTURA 1
int global_PID = 1000;

int check_fd(int fd, int permissions)
{
  if (fd!=1) return -9; /*EBADF*/
  if (permissions!=ESCRIPTURA) return -13; /*EACCES*/
  return 0;
}

int sys_ni_syscall()
{
	return -38; /*ENOSYS*/
}

int sys_getpid()
{
	return current()->PID;
}
 
int ret_from_fork()
{
	return 0;
}


int sys_fork()
{
	// creates the child process
	
	if (list_empty(&freequeue)) return -12; //ENOMEM

	struct task_struct *new_proc = list_head_to_task_struct(list_first(&freequeue));
	list_del(list_first(&freequeue)); //treiem el proces de la cua free
	
	//Creem task unions pel pare i el fill
	union task_union *son_stack = (union task_union*) new_proc;
	union task_union *dad_stack = (union task_union*) current();

	copy_data(dad_stack, son_stack, sizeof(union task_union));
	allocate_DIR((struct task_struct*)son_stack); //donem pagines al fill
	
	// Cercar pagines per la dades + pila


	
	page_table_entry *TP_proc_child = get_PT(&son_stack->task); //primera pagina del fill

	int i,j,pag;
	for (i = 0; i < NUM_PAG_DATA; i++) {
		pag = alloc_frame();
		if (pag != -1) { 
			//Pagina lliure		
			// PAG_LOG_INIT_DATA, PAG_LOG_INIT_CODE+NUM_PAG_CODE (mm_address.h)
			set_ss_pag(TP_proc_child,PAG_LOG_INIT_DATA+i, pag);
		}
		else {
			//No pagina lliure
			for (j=0; j < i; j++) { //alliberem el que hem omplert
				free_frame(get_frame(TP_proc_child, PAG_LOG_INIT_DATA + j));
				del_ss_pag(TP_proc_child, PAG_LOG_INIT_DATA + j);
			}
			
			list_add_tail(&new_proc->list, &freequeue);
			return -11;  //EAGAIN 
		}
	}
	
	page_table_entry *TP_proc_dad  = get_PT(current()); //Taula de pagines del pare
	for (i = 0; i < NUM_PAG_KERNEL; i++) { // Copiem les pagines de Kernel al fill
		set_ss_pag(TP_proc_child, i, get_frame(TP_proc_dad,i));
	}
	
	for (i = 0; i < NUM_PAG_CODE; i++) { // Copiem les pagines de Codi del pare al fill
		set_ss_pag(TP_proc_child, PAG_LOG_INIT_CODE + i, get_frame(TP_proc_dad,PAG_LOG_INIT_CODE + i));
	}
	
	for (i = NUM_PAG_KERNEL + NUM_PAG_CODE; i < NUM_PAG_KERNEL + NUM_PAG_CODE + NUM_PAG_DATA; i++) {
		// Copiar les pagines de dades del pare al fill
		set_ss_pag(TP_proc_dad, NUM_PAG_DATA + i, get_frame(TP_proc_child, i)); //Creem enllaç
		copy_data((void*)(i<<12), (void*)((NUM_PAG_DATA + i) << 12), PAGE_SIZE); //Copiem dades
		del_ss_pag(TP_proc_dad, NUM_PAG_DATA + i); //Eliminem enllaç
	}
	
	//Prohibim l'acces del pare a les pagines del fill
	
	set_cr3(get_DIR(current()));       
        
        
        //Inicialitzem les variables que no son comuns de pare i fill
        son_stack->task.PID = ++global_PID;
        son_stack->task.state = ST_READY;
        
        int register_ebp;
        __asm__ __volatile__ (
            "movl %%ebp, %0\n\t"
            : "=g" (register_ebp)
            : );
        register_ebp -= (int)current();
        register_ebp += (int)son_stack;
        
        //Posició inicial de la pila
        son_stack->task.register_esp=register_ebp + sizeof(DWord);
        
        //Pujem una posicio per guardar ret_from_fork, que es un 0
        son_stack->task.register_esp-=sizeof(DWord);
        *(DWord*)(son_stack->task.register_esp)=(DWord)&ret_from_fork;

        //Pujem una posicio per guardar el valor l'
        son_stack->task.register_esp-=sizeof(DWord);
        *(DWord*)(son_stack->task.register_esp)= *(DWord*)register_ebp;
        
        init_stats(&(son_stack->task.p_stats));
        
        //Afegim el fill a la cua de ready
	list_add_tail(&(son_stack->task.list),&readyqueue);

  	return son_stack->task.PID;
}

void sys_exit()
{ 

	int i;
	page_table_entry *TP_current = get_PT(current());
	
	for (i = 0; i < NUM_PAG_DATA; ++i) {
		free_frame(get_frame(TP_current, PAG_LOG_INIT_DATA + i));
		del_ss_pag(TP_current, PAG_LOG_INIT_DATA + i);
	}
	
	list_add_tail(&(current()->list), &freequeue);
	current()->PID = -1;
        
        sched_next_rr();
}

#define TAM_BUFF 4096

int sys_write (int fd, char * buffer, int size) {
	char buff[TAM_BUFF];
	int bytes_left;
	int ret = check_fd(fd, ESCRIPTURA);
	if (ret != 0) return ret;
	if (!access_ok(VERIFY_READ, buffer, size)) return -EFAULT;
	if (size < 0) return -EINVAL;
	bytes_left = size;
	while (bytes_left > TAM_BUFF) {
		copy_from_user(buffer, buff, TAM_BUFF);
		ret = sys_write_console(buff,TAM_BUFF);
		bytes_left -= ret;
		buffer += ret;
	}
	if (bytes_left > 0) {
		copy_from_user(buffer, buff, bytes_left);
		ret = sys_write_console(buff, bytes_left);
		bytes_left -= ret;
	}
	return (size - bytes_left);
}

int sys_gettime () {
	extern int zeos_ticks;
	return zeos_ticks;
}


extern int remaining_quantum;

int sys_get_stats(int pid, struct stats *st)
{
  int i;
  
  //Mirem que no estigui protegit d'escriptura
  if (!access_ok(VERIFY_WRITE, st, sizeof(struct stats))) return -EFAULT; 
  
  if (pid<0) return -22; //EINVAL
  for (i=0; i<NR_TASKS; i++)
  {
    if (task[i].task.PID==pid)
    {
      task[i].task.p_stats.remaining_ticks=remaining_quantum;
      copy_to_user(&(task[i].task.p_stats), st, sizeof(struct stats));
      return 0;
    }
  }
  return -3; ///ESRCH
}
	






