// #include <sys/ptrace.h>
// #include <sys/types.h>
// #include <sys/wait.h>
// #include <unistd.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/user.h>
// #include <sys/reg.h>
// #include <fcntl.h>
// #include <sys/stat.h>
// #include <sys/syscall.h>   /* For SYS_write etc */
// #include <glob.h>
// #include <errno.h>
// #include <string.h>
// #include <limits.h>

// //char* myname;

// // int globerr(const char *path, int eerrno)
// // {
// // 	fprintf(stderr, "%s: %s\n", path, strerror(eerrno));
// // 	return 0;	/* let glob() keep going */
// // }

//  int main(int argc, char** argv)
//  { 
// 	int i;
// 	int flags = 0;
// 	glob_t results;
// 	int ret;

// 	if (argc == 1) {
// 		fprintf(stderr, "usage: %s wildcard ...\n", argv[0]);
// 		exit(1);
// 	}

// 	//myname = argv[0];	/* for globerr() */

// 	for (i = 1; i < argc; i++) {
// 		flags |= (i > 1 ? GLOB_APPEND : 0);
// 		ret = glob(argv[i], flags, globerr, & results);
// 		if (ret != 0)
// 			break;
// 	}

// 	for (i = 0; i < results.gl_pathc; i++)
// 		printf("%s\n", results.gl_pathv[i]);

// 	globfree(& results);
// 	return 0;
// }
  // printf("%lu\n",sizeof(long));
  // return 0;
  // int a = open("a.txt", O_WRONLY | O_CREAT, S_IRWXU);
  // char *buf = "bash";
  // char *buff;
  // if(a < 0)
  // 	perror("open error: ");
  // int b = write(a, buf, sizeof(buf));
  // if(b < 0)
 	//  perror("write error: ");
  // int c = read(a, buff, sizeof(buf));
  // char buffer[PATH_MAX + 1]; /* not sure about the "+ 1" */
  // char *res = realpath("a.txt", buffer);
  // if (res) {
  //     //printf("a.txt is at %s.\n", buffer);
  //   return 0;
  // } else {
  //     perror("realpath");
  //     exit(EXIT_FAILURE);
  // }


 //	pid_t child;
//     long orig_rax, rax;
//     //long params[3];
//     struct user_regs_struct regs;
//     int status;
//     int insyscall = 0;
//     child = fork();
//     if(child < 0)
//     	printf("fork failed\n");
//     if(child == 0) 
//     {
//     	//printf("got here with child = %d\n",child);
//         ptrace(PTRACE_TRACEME, 0, NULL, NULL);
//         execl("/bin/ls","ls", NULL);
//     }
//     else 
//     {
//        while(1) 
//        {
//           wait(&status);
//           if(WIFEXITED(status))
//           {
//           	//printf("process : %d exited\n", child);
//             break;
//           }
//           orig_rax = ptrace(PTRACE_PEEKUSER,child, 8 * ORIG_RAX, NULL);
//           // if(orig_rax != -1)
//           //  	printf(stderr,"%s\n",explain_ptrace(PTRACE_PEEKUSER,child, 8 * ORIG_RAX, NULL) );
//           if(orig_rax == SYS_write) 
//           {
//              if(insyscall == 0) 
//              {
//                  Syscall entry 
//                 insyscall = 1;
//                 //printf("got here!\n");
//                 // params[0] = ptrace(PTRACE_PEEKUSER,child, 8 * RDI,NULL);
                
//                 // params[1] = ptrace(PTRACE_PEEKUSER,child, 8 * RSI,NULL);
                
//                 // params[2] = ptrace(PTRACE_PEEKUSER,child, 8 * RDX,NULL);
//                 ptrace(PTRACE_GETREGS, child, NULL, &regs);

//                 printf("write called with %llu, %llu, %llu\n", regs.rdi, regs.rsi, regs.rdx);
//               } 
//               else 
//               { /* Syscall exit */
//                 rax = ptrace(PTRACE_PEEKUSER,
//                              child, 8 * RAX, NULL);
//                     printf("write returned with %ld\n", rax);
//                     insyscall = 0;
//               }
//            }
//             ptrace(PTRACE_SYSCALL,
//                    child, NULL, NULL);
//        }
//     }
//     return 0;
// }
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
  // char *newargv[] = { NULL, "hello", "world", NULL };
  // char *newenviron[] = { NULL };

  // if (argc != 2)
  // {
  //   fprintf(stderr, "Usage: %s <file-to-exec>\n", argv[0]);
  //   exit(EXIT_FAILURE);
  // }
  // newargv[0] = argv[1];

  execv(argv[2], argv+1);
  perror("execve"); /* execve() only returns on error */
  exit(EXIT_FAILURE);
}