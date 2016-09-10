#include <sys/ptrace.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fnmatch.h>
#include <fcntl.h>

typedef struct{
char path[256];
int size;
int permit[3];
}Line;

struct sandbox {
  pid_t child;
  const char *progname;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};

Line* parseConfigFile(char *name, Line *oneLine)
{
  int n = 0;
  int i = 3;
  int j = 0;
  oneLine = (Line*)malloc(sizeof(Line));
  //oneLine[0] = (Line*)malloc(sizeof(Line));
  FILE *fp = fopen(name,"r");
  char buf[4096];
  //read a line
  while(fgets(buf,sizeof(buf),fp)){
    oneLine[n].permit[0] = buf[0] - '0';//character to int character - '0'
    oneLine[n].permit[1] = buf[1] - '0';
    oneLine[n].permit[2] = buf[2] - '0';
    while(buf[i] == ' '){
      i++;
    }
    j = i;
    while((buf[i] != '\n') && (buf[i] != '\0')/*(i < strlen(buf))*/) 
    {
      oneLine[n].path[i-j] = buf[i];
      i++;
    }
    i = 3;
    j = 0;
    n++;
    oneLine = realloc(oneLine,(n+1)*sizeof(Line));
  }
  oneLine[0].size = n;
  return oneLine; 
}

int* pathcmp(char *sysCallPath, Line *oneLine){
  int *permissions = (int*)malloc(sizeof(int)*3);
  int i = 0;
  for(i = 0; i < oneLine[0].size; i++)
  {
    if(fnmatch(oneLine[i].path, sysCallPath, FNM_PATHNAME) == 0)
    {
      permissions[0] = oneLine[i].permit[0];
      permissions[1] = oneLine[i].permit[1];
      permissions[2] = oneLine[i].permit[2];
    }
  }
  return permissions;
}


void writeHandler(struct sandbox* sandb, struct user_regs_struct *regs){
  char fdpath[256];
  char filepath[256];
  int size;
  //printf("write 1\n");
  sprintf(fdpath,"/proc/%u/fd/%llu",sandb->child,regs->rdi);
  size = readlink(fdpath, filepath, 256);  //this gives the filepath for a particular fd
  if(size != -1)
  {
    filepath[size] = '\0';
    printf("WROTE ON File-%s-\n", filepath);
  }
  else
    printf("WRITE HANDLER ERROR: %s\n", strerror(errno));
  //return -EACCES;
}

void readHandler(struct sandbox* sandb, struct user_regs_struct *regs){
  //printf("read0\n");
  char fdpath[256], filepath[256];
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sandb->child,regs->rdi);
  size = readlink(fdpath, filepath, 512);
  if(size != -1)
  {
    filepath[size] = '\0';
    printf("READ File-%s-\n", filepath);
  }
  else
  {
    printf("READ HANDLER ERROR : %s\n", strerror(errno));
  }
  //return -EACCES;
}

void openHandler(struct sandbox* sandb, struct user_regs_struct *regs){

  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("OPEN HANDLER ERROR: %s\n",strerror(errno));
          break;
      }
      memcpy(val + read, &tmp, sizeof tmp);
      if (memchr(&tmp, 0, sizeof tmp) != NULL){
          if(read == 0)
            val[sizeof(tmp)] = '\0';
          else
            val[read] = '\0';
          break;
        }
      read += sizeof tmp;
  }
  printf("OPENED: %s\n", val);

  //return -EACCES;
}

struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            readHandler},
  {__NR_write,           writeHandler},
  {__NR_exit,            NULL},
  {__NR_brk,             NULL},
  {__NR_mmap,            NULL},
  {__NR_access,          NULL},
  {__NR_open,            openHandler},
  {__NR_fstat,           NULL},
  {__NR_close,           NULL},
  {__NR_mprotect,        NULL},
  {__NR_munmap,          NULL},
  {__NR_arch_prctl,      NULL},
  {__NR_exit_group,      NULL},
  {__NR_getdents,        NULL},
};



void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int i;
  struct user_regs_struct regs;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall) {
      if(sandb_syscalls[i].callback != NULL)
        sandb_syscalls[i].callback(sandb, &regs);
      return;
    }
  }

  if(regs.orig_rax == -1) {
    printf("[SANDBOX] Segfault ?! KILLING !!!\n");
  } //else {
  //    printf("[SANDBOX] Trying to use devil syscall (%llu) ?!? KILLING !!!\n", regs.orig_rax);
  // }
  //sandb_kill(sandb);
}

void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;

  pid = fork();

  if(pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

  if(pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

    if(execvp(argv[0], argv) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");

  } else {
    sandb->child = pid;
    sandb->progname = argv[0];
    wait(NULL);
  }
}

void sandb_run(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->child, &status, __WALL | WNOHANG); //I don't get these options.
      sandb_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
  }

  wait(&status);

  if(WIFEXITED(status))
    exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status)) {
    sandb_handle_syscall(sandb);
  }
}

int main(int argc, char **argv) {
  struct sandbox sandb;

  Line *commands = parseConfigFile("config",commands);
  
  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  sandb_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandb_run(&sandb);
  }

  free(commands);
  // return EXIT_SUCCESS;
}
