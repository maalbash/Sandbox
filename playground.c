#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>   /* For SYS_write etc */
int main()
{   pid_t child;
    long orig_rax, rax;
    //long params[3];
    struct user_regs_struct regs;
    int status;
    int insyscall = 0;
    child = fork();
    if(child < 0)
    	printf("fork failed\n");
    if(child == 0) 
    {
    	//printf("got here with child = %d\n",child);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls","ls", NULL);
    }
    else 
    {
       while(1) 
       {
          wait(&status);
          if(WIFEXITED(status))
          {
          	//printf("process : %d exited\n", child);
            break;
          }
          orig_rax = ptrace(PTRACE_PEEKUSER,child, 8 * ORIG_RAX, NULL);
          // if(orig_rax != -1)
          //  	printf(stderr,"%s\n",explain_ptrace(PTRACE_PEEKUSER,child, 8 * ORIG_RAX, NULL) );
          if(orig_rax == 1) 
          {
             if(insyscall == 0) 
             {
                /* Syscall entry */
                insyscall = 1;
                //printf("got here!\n");
                // params[0] = ptrace(PTRACE_PEEKUSER,child, 8 * RDI,NULL);
                
                // params[1] = ptrace(PTRACE_PEEKUSER,child, 8 * RSI,NULL);
                
                // params[2] = ptrace(PTRACE_PEEKUSER,child, 8 * RDX,NULL);
                ptrace(PTRACE_GETREGS, child, NULL, &regs);

                printf("write called with %llu, %llu, %llu\n", regs.rdi, regs.rsi, regs.rdx);
              } 
              else 
              { /* Syscall exit */
                rax = ptrace(PTRACE_PEEKUSER,
                             child, 8 * RAX, NULL);
                    printf("write returned with %ld\n", rax);
                    insyscall = 0;
              }
           }
            ptrace(PTRACE_SYSCALL,
                   child, NULL, NULL);
       }
    }
    return 0;
}
