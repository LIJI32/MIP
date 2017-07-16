#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <stdbool.h>
#include "inject/inject.h"

int main(int argc, const char **argv)
{
    bool wait_for_process = false;
    if (argc == 4 && strcmp(argv[3], "-w") == 0) {
        argc = 3;
        wait_for_process = true;
    }
    
    if (argc != 3) {
        fprintf(stderr, "Usage: %s pid/name dylib [-w]\n", argv[0]);
        exit(-1);
    }
    
    mach_port_t task = 0;
    int pid = atoi(argv[1]);
    if (pid == 0) {
        do {
            fprintf(stderr, "Searching...\n");
            if (strlen(argv[1]) > 16) {
                fprintf(stderr, "Searching for process by name is currently not supported "
                                "for names longer than 16 characters. Use PID instead. \n");
                exit(-1);
            }
            
            int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
            size_t buf_size = 0;
            
            if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &buf_size, NULL, 0) < 0) {
                perror("Failure calling sysctl");
                return errno;
            }
            
            struct kinfo_proc *kprocbuf = malloc(buf_size);
            if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), kprocbuf, &buf_size, NULL, 0) < 0) {
                perror("Failure calling sysctl");
                return errno;
            }
            
            size_t count = buf_size / sizeof(kprocbuf[0]);
            for (int i = 0; i < count; i++) {
                if (strcmp(kprocbuf[i].kp_proc.p_comm, argv[1]) == 0) {
                    pid = kprocbuf[i].kp_proc.p_pid;
                    break;
                }
            }
            
            free(kprocbuf);
        } while (pid == 0 && wait_for_process);
    }

    else if (wait_for_process) {
        fprintf(stderr, "-w must be used with a process name, not PID\n");
        exit(-1);
    }
    
    if (pid == 0) {
        fprintf(stderr, "Failed to find process named %s.\n", argv[1]);
        exit(-1);
    }
    
    fprintf(stderr, "Injecting to process %d\n", pid);
    
    kern_return_t ret = KERN_SUCCESS;
    
    if ((ret = task_for_pid(mach_task_self(), pid, &task))) {
        fprintf(stderr, "Failed to get task for pid %d (error %x). Make sure %s is signed correctly or run it as root.\n", pid, ret, argv[0]);
        exit(ret);
    }
    
    ret = inject_to_task(task, argv[2]);
    if (ret) {
        fprintf(stderr, "Injection failed with error %x.\n", ret);
        exit(ret);
    }
    
    /* This interrupts blocking system calls to ensure execution. */

    if (ptrace(PT_ATTACH, pid, 0, 0) == -1) {
        perror("PT_ATTACH failed");
        fprintf(stderr, "Injection succeeded, but the injected library will only run after the main thread wakes up\n");
        return errno;
    }
    wait(NULL);
    if (ptrace(PT_DETACH, pid, 0, 0) == -1) {
        perror("PT_DETACH failed");
        return errno;
    }
    
    fprintf(stderr, "Done injecting to process %d\n", pid);
    
    return 0;
}
