#include <libc.h>
#include <segment.h>
#include <types.h>
#include <interrupt.h>
#include <hardware.h>
#include <system.h>
#include <sched.h>
#include <mm.h>
#include <io.h>
#include <utils.h>

char buff[24];

int pid;

int __attribute__ ((__section__(".text.main")))
  main(void)
{
    /* Next line, tries to move value 0 to CR3 register. This register is a privileged one, and so it will raise an exception */
     /* __asm__ __volatile__ ("mov %0, %%cr3"::"r" (0) ); */
	
        /*int i = fork();
	if (i != -1) write(1,"hola", sizeof("hola"));
	else write (1, "adeu", sizeof("adeu"));*/
    
  int j = 0;      
  while(j < 10) {
      int i = fork();
	if (i != -1) write(1,"hola", sizeof("hola"));
	else write (1, "adeu", sizeof("adeu"));
        ++j;
}
}
