#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include "injectd_client/injectd_client.h"

int main(int argc, const char **argv)
{
    bool wait_for_process = false;
    unsigned delay = 0;
    if (argc == 4 && argv[3][0] == '-' && argv[3][1] == 'w') {
        argc = 3;
        delay = atoi(argv[3] + 2);
        wait_for_process = true;
    }
    
    if (argc != 3) {
        fprintf(stderr, "Usage: %s pid/name dylib [-w[delay]]\n", argv[0]);
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
    
    if (delay) {
        sleep(delay);
    }
    
    fprintf(stderr, "Injecting to process %d\n", pid);
        
    const char *error = inject_to_pid(pid, argv[2], true);
    if (error) {
        fprintf(stderr, "Injection failed: %s\n", error);
        exit(1);
    }
        
    return 0;
}
