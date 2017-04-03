/*
 * libc.c 
 */

#include <libc.h>

#include <types.h>

#include <errno.h>

int errno;

void itoa(int a, char *b)
{
  int i, i1;
  char c;
  
  if (a==0) { b[0]='0'; b[1]=0; return ;}
  
  i=0;
  while (a>0)
  {
    b[i]=(a%10)+'0';
    a=a/10;
    i++;
  }
  
  for (i1=0; i1<i/2; i1++)
  {
    c=b[i1];
    b[i1]=b[i-i1-1];
    b[i-i1-1]=c;
  }
  b[i]=0;
}

int strlen(char *a)
{
  int i;
  
  i=0;
  
  while (a[i]!=0) i++;
  
  return i;
}


int write (int fd, char *buffer, int size) {
	int resultat;
	__asm__ __volatile__ (
	"int $0x80"
	: "=a" (resultat)
	: "a" (4), 
	"b" (fd), 
	"c" (buffer), 
	"d" (size)
	);
	
	if (resultat < 0) {
			errno = -resultat;
			return -1;
	}
	errno = 0;
	return resultat; 
}

int gettime() {
	int res;
	__asm__ __volatile__ (
	"int $0x80"
	: "=a" (res)
	: "a" (10)
	);
	if(res < 0){
			errno = res;
			return -1;
	}
	return res;
}

int getpid() {
	int pid;
	__asm__ __volatile__ (
	"int $0x80"
	: "=a" (pid)
	: "a" (20)
	);
	errno = 0;
	return pid;
}

int fork() {
	int pid;
	__asm__ __volatile__ (
	"int $0x80"
	: "=a" (pid)
	: "a" (2)
	);
	if (pid < 0) {
		errno = -pid;
		return -1;
	}	
	errno = 0;
	return pid;
}

void exit() {
	__asm__ __volatile__ (
	"int $0x80"
	:
	: "a" (1)
	);
}



int get_stats(int pid, struct stats *st)
{
	int result;
	__asm__ __volatile__ (
		"int $0x80 \n\t"
		:"=a" (result)
		:"a" (35), "b" (pid), "c" (st) );
	if (result < 0) {
		errno = -result;
		return -1;
	}
	errno = 0;
	return result;
}

void perror () {
	switch (errno) {
			case 9:
				write (1,"Bad file number", strlen("Bad file number"));
				break;
				
			case 14:
				write (1,"Bad address", strlen("Bad address"));
				break;
				
			case 22:
				write (1,"Invalid argument", strlen("Invalid argument"));
				break;
				
			case 38:
				write (1,"Function not implemented", strlen("Function not implemented"));
				break;
	}
}
