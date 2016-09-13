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
#include <errno.h>
#include <limits.h>

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
  void (*callback)(struct sandbox*, struct user_regs_struct *regs, Line* oneLine);
};

Line* parseConfigFile(char *name, Line *oneLine)
{
  int n = 0;
  int i = 3;
  int j = 0;
  oneLine = (Line*)malloc(sizeof(Line));
  //oneLine[0] = (Line*)malloc(sizeof(Line));
  FILE *fp = fopen(name,"r");
  if(fp == NULL){
    printf("Couldn't find the config file: %s\n", strerror(errno));
    return NULL;
  }
  char buf[4096];
  //read a line
  while(fgets(buf,sizeof(buf),fp)){
    oneLine[n].permit[0] = buf[0] - '0'; //character to int character - '0'
    oneLine[n].permit[1] = buf[1] - '0';
    oneLine[n].permit[2] = buf[2] - '0';
    while((buf[i] == ' ') || (buf[i] == '\t')){
      i++;
    }
    j = i;
    while((buf[i] != '\n') && (buf[i] != '\0')) 
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
  int *permissions = (int*)malloc(sizeof(int)*4);
  int i = 0;
  for(i = 0; i < oneLine[0].size; i++)
  {
    if(fnmatch(oneLine[i].path, sysCallPath, FNM_PATHNAME) == 0)
    {
      permissions[0] = 1;
      permissions[1] = oneLine[i].permit[0];
      permissions[2] = oneLine[i].permit[1];
      permissions[3] = oneLine[i].permit[2];
    }
  }
  //printf("%d %d %d\n", oneLine[0].permit[0], oneLine[0].permit[1], oneLine[0].permit[2]);
  if(permissions[0] != 1)
    permissions[0] = 0;
  return permissions;
}

void linkHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  
  char oldbuffer[PATH_MAX + 1];
  char *oldres;
  char *oldval = malloc(4096);
  int oldallocated = 4096;
  int oldread = 0;
  unsigned long oldtmp;
  int *oldx;
  while (1) {
      if (oldread + sizeof oldtmp > oldallocated) {
          oldallocated *= 2;
          oldval = realloc(oldval, oldallocated);
      }
      oldtmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + oldread);
      if(errno != 0) {
          oldval[oldread] = 0;
          printf("link HANDLER ERROR: %s\n",strerror(errno));
          break;
      }
      memcpy(oldval + oldread, &oldtmp, sizeof oldtmp);
      if (memchr(&oldtmp, 0, sizeof oldtmp) != NULL){
          if(oldread == 0)
            oldval[sizeof(oldtmp)] = '\0';
          else
            oldval[oldread] = '\0';
          break;
        }
      oldread += sizeof oldtmp;
  }
  oldres = realpath(oldval,oldbuffer);
  oldbuffer[strlen(oldbuffer)-strlen(oldval)] = '\0';
  oldx = pathcmp( oldbuffer, oneLine);
  if(oldx[0] == 1)
  {
    if(oldx[3] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (link) because (execute) is not allowed: %s\n", strerror(errno));
    }
    if(oldx[2] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (link) because (write) is not allowed: %s\n", strerror(errno));
    }
  }
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rsi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("link HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);

  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[2] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (link) because (write) is not allowed: %s\n", strerror(errno));
    }
  }
}

void unlinkHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("unlink HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  buffer[strlen(buffer)-strlen(val)] = '\0';
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[2] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (unlink) because (write) is not allowed: %s\n", strerror(errno));
    }
  }
}

void renameHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("rename HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  buffer[strlen(buffer)-strlen(val)] = '\0';

  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[2] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (rename) because (write) is not allowed: %s\n", strerror(errno));
      return;
    }
  }
  read = 0;
  allocated = 4096;
  val = realloc(val, 4096);
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rsi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("rename HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  buffer[strlen(buffer)-strlen(val)] = '\0';

  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[2] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (rename) because (write) is not allowed: %s\n", strerror(errno));
    }
  }
}

void accessHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : https://github.com/nelhage/ministrace/blob/master/ministrace.c
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("access HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if((regs->rsi & R_OK) == R_OK)
    {
      if(x[1] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (access) because (read) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rsi & W_OK) == W_OK)
    {
      if(x[2] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (access) because (write) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rsi & X_OK) == X_OK)
    {
      if(x[3] == 0) 
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (access) because (execute) is not allowed: %s\n", strerror(errno));
      }
    }
  }
}

void chdirHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : https://github.com/nelhage/ministrace/blob/master/ministrace.c
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("chdir HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[3] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (chdir) because (execute) is not allowed: %s\n", strerror(errno));
    }
  }
}

void rmdirHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : https://github.com/nelhage/ministrace/blob/master/ministrace.c
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("rmdir HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  buffer[strlen(buffer)-strlen(val)] = '\0';
  
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[3] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (rmdir) because (execute) is not allowed: %s\n", strerror(errno));
    }
  }
}

void mkdirHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : https://github.com/nelhage/ministrace/blob/master/ministrace.c
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("mkdir HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  buffer[strlen(buffer)-strlen(val)] = '\0';
  
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[3] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (mkdir) because (execute) is not allowed: %s\n", strerror(errno));
    }
  }
}

void writeHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : http://stackoverflow.com/questions/33431994/extracting-system-call-name-and-arguments-using-ptrace
  char fdpath[256];
  char filepath[256];
  int size;
  //printf("write 1\n");
  sprintf(fdpath,"/proc/%u/fd/%llu",sandb->child,regs->rdi);
  size = readlink(fdpath, filepath, 256);  //this gives the filepath for a particular fd
  if(size != -1)
  {
    filepath[size] = '\0';
    printf("WROTE ON File: %s\n", filepath);
  }
  else
    printf("WRITE HANDLER ERROR: %s\n", strerror(errno));
  //return -EACCES;
}

void readHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //printf("read0\n");
  char fdpath[256], filepath[256];
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sandb->child,regs->rdi);
  size = readlink(fdpath, filepath, 512);
  if(size != -1)
  {
    filepath[size] = '\0';
    printf("READ File: %s\n", filepath);
  }
  else
  {
    printf("READ HANDLER ERROR : %s\n", strerror(errno));
  }
  //return -EACCES;
}

void openHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  //source : https://github.com/nelhage/ministrace/blob/master/ministrace.c
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
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
  res = realpath(val,buffer);
  
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if((regs->rsi & O_RDONLY) == O_RDONLY)
    {
      if(x[1] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (open) because (read) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rsi & O_WRONLY) == O_WRONLY)
    {
      if(x[2] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (open) because (write) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rsi & O_RDWR) == O_RDWR)
    {
      if((x[1] == 0) || (x[2] == 0))
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (open) because (read & write) are not allowed: %s\n", strerror(errno));
      }
    }
  }
    //printf("OPENED: %s\n", buffer);
}

void execHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rdi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("EXECVE HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);

  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if(x[3] == 0)
    {
      kill(sandb->child, SIGKILL);
      errno = EACCES;
      fprintf(stderr,"fend stopped (execve) because (execute) is not allowed: %s\n", strerror(errno));
    }
  }
}

void openatHandler(struct sandbox* sandb, struct user_regs_struct *regs, Line *oneLine){
  // printf("openat call %llu %llu %llu %llu\n", regs->rax, regs->rdi, regs->rsi, regs->rdx);
  // printf("%d\n", O_RDONLY + O_NONBLOCK + O_DIRECTORY + O_CLOEXEC);
  char buffer[PATH_MAX + 1];
  char *res;
  char *val = malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  int *x;
  while (1) {
      if (read + sizeof tmp > allocated) {
          allocated *= 2;
          val = realloc(val, allocated);
      }
      tmp = ptrace(PTRACE_PEEKDATA, sandb->child, regs->rsi + read);
      if(errno != 0) {
          val[read] = 0;
          printf("OPENAT HANDLER ERROR: %s\n",strerror(errno));
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
  res = realpath(val,buffer);
  //printf("%s\n", buffer);
  x = pathcmp( buffer, oneLine);
  if(x[0] == 1)
  {
    if((regs->rdx & O_RDONLY) == O_RDONLY)
    {
      if(x[1] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (openat) because (read) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rdx & O_WRONLY) == O_WRONLY)
    {
      if(x[2] == 0)
      {
        kill(sandb->child, SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (openat) because (write) is not allowed: %s\n", strerror(errno));
      }
    }
    if((regs->rdx & O_RDWR) == O_RDWR)
    {
      if((x[1] == 0) || (x[2] == 0))
      {
        kill(sandb->child,SIGKILL);
        errno = EACCES;
        fprintf(stderr,"fend stopped (openat) because (read & write) are not allowed: %s\n", strerror(errno));
      }
    }
  }
    //printf("OPENED: %s\n", buffer);
}


struct sandb_syscall sandb_syscalls[] = {
  {__NR_rmdir,           rmdirHandler},
  {__NR_mkdir,           mkdirHandler},
  {__NR_chdir,           chdirHandler},
  {__NR_execve,          execHandler},
  {__NR_open,            openHandler},
  {__NR_openat,          openatHandler},
  {__NR_access,          accessHandler},
  {__NR_rename,          renameHandler},
  {__NR_unlink,          unlinkHandler},
  {__NR_link,            linkHandler},
};



void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb, Line *oneLine) {
  int i;
  struct user_regs_struct regs;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall) {
      if(sandb_syscalls[i].callback != NULL)
        sandb_syscalls[i].callback(sandb, &regs, oneLine);
      return;
    }
  }

  if(regs.orig_rax == -1) {
    printf("[SANDBOX] Segfault ?! KILLING !!!\n");
  } 
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

void sandb_run(struct sandbox *sandb, Line *oneLine) {
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
    sandb_handle_syscall(sandb,oneLine);
  }
}

int main(int argc, char **argv) {
  struct sandbox sandb;
  Line *commands;

  if(argc < 2) 
  {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c configuration_file] <command> [args]", argv[0]);
  }
  
  if(strcmp(argv[1],"-c") == 0)
  {
    commands = parseConfigFile(argv[2],commands);
    sandb_init(&sandb, argc-3, argv+3);
  }
  else
  {
    commands = (Line*)malloc(sizeof(Line));
    commands[0].size = 0;
    commands[0].path[0] = '\0';
    commands[0].permit[0] = 1;
    commands[0].permit[1] = 1;
    commands[0].permit[2] = 1;
    sandb_init(&sandb, argc-1, argv+1);
  }
  

  for(;;) {
    sandb_run(&sandb, commands);
  }

  free(commands);

  return EXIT_SUCCESS;
}
