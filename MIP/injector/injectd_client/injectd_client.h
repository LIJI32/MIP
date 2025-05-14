#include <stdbool.h>
#include <sys/types.h>

const char *inject_to_pid(pid_t pid, const char *dylib, bool interrupt_syscalls);
