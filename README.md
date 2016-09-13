# p-sandbox
A ptrace based sandbox. (PoC)

--------------------------------


This is a small sandbox to limit the number of allowed syscalls for a process.


## To compile :

$ make


## To run :

$ ./fend [-c configfile] < sandboxed process > [args]


##If an offending process is found, the sandbox simply kills the process.
