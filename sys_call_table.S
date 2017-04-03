#include <asm.h>
#include <segment.h>

ENTRY (sys_call_table)
	.long sys_ni_syscall	//0
	.long sys_exit		//1
	.long sys_fork		//2
	.long sys_ni_syscall	//3
	.long sys_write		//4
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall	//9
	.long sys_gettime	//10
	.long sys_ni_syscall
	.long sys_ni_syscall	//12
	//.long sys_yield		//13
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_getpid	//20
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall
	.long sys_ni_syscall	//34
	//.long sys_get_stats	//35

.globl MAX_SYSCALL
MAX_SYSCALL = (. - sys_call_table)/4
