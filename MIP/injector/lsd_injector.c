#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/syslimits.h>

#include <loader/loader.h>
#import <mach-o/loader.h>
#import <mach-o/dyld.h>
#include "inject/inject.h"

// Private APIs
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t, const char *);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);

uint64_t handleClientMessageHook_Sierra(void *this, uint64_t command, xpc_object_t dict);
typeof(handleClientMessageHook_Sierra) *handleClientMessageOrig_Sierra;

uint64_t handleClientMessageHook_HighSierra(void *this, void *session, xpc_connection_t connection, xpc_object_t dict);
typeof(handleClientMessageHook_HighSierra) *handleClientMessageOrig_HighSierra;

/* We want the user data to be accessible from all processes, but some processes (for
   example, Chrome's sub-processes) have a very strict sandbox profile so putting the
   data in the user's home folder won't always work. /usr/lib, on the other hand, is
   accessible from all processes (Otherwise they're pretty much worthless to hook in
   the first place), so we put our data in /usr/lib/mip/user_data/<uid>/. We also set
   a symlink in the user's Library folder, for easier access. */
void create_user_data_folder(pid_t pid)
{
    struct proc_bsdinfo proc;
    proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc, sizeof(proc));
    
    char path[USER_DATA_PATH_MAX];
    sprintf(path, USER_DATA_ROOT "/%d", proc.pbi_uid);
    
    if (mkdir(path, 0755)) return; // Might already exist
    chown(path, proc.pbi_uid, proc.pbi_gid);
    
    struct passwd *pw = getpwuid(proc.pbi_uid);
    char library_path[PATH_MAX];
    if (snprintf(library_path, sizeof(library_path), "%s/Library/MIP", pw->pw_dir) < sizeof(library_path)) {
        symlink(path, library_path);
        lchown(library_path, proc.pbi_uid, proc.pbi_gid);
    }
}

void handleClientMessageHook_common(uint64_t command, xpc_object_t dict)
{
    /* Command 500 is sent by all GUI processes to launchservicesd when they launch.
       The process will block until it receives an answer from launchservicesd.
       We will inject our code before we send a reply. Once we send the actual reply,
       by calling the original method, the process resumes, runs the injected dlopen,
       and continues normal execution. */
    
    if (command == 500) {
        audit_token_t token;
        xpc_dictionary_get_audit_token(dict, &token);
        pid_t pid = audit_token_to_pid(token);
        
        /* While strictly speaking this should be loader's responsibility to create this folder,
           this function must run as root, so it is done by the injector. */
        create_user_data_folder(pid);
        
        /* Before 10.12, the xpc dict also included a apptaskport key with task port send rights.
           In 10.11 this could be considered a vulnerability - if you managed to receive this
           xpc message, by setting up a fake launchservicesd daemon or managing to inject code to
           the real one, you could completely bypass the need for task_for_pid and get a task port
           for rootless/SIP-protected processes, something that wouldn't be possible under SIP
           even as root. Not sure if this possible vulnerability is the reason Apple removed this
           key, it could be just some code cleanup.
         */
        mach_port_t task = xpc_dictionary_copy_mach_send(dict, "apptaskport");
        
        if (!task) {
            task_for_pid(mach_task_self(), pid, &task);
        }
        inject_to_task(task, "/Library/Apple/System/Library/Frameworks/mip/loader.dylib");
        mach_port_destroy(mach_task_self(), task);
    }
}

uint64_t xpc_dictionary_get_int64_hook(xpc_object_t dict, const char *key)
{
    uint64_t ret = xpc_dictionary_get_int64(dict, key);
    if (strcmp(key, "command") == 0) {
        handleClientMessageHook_common(ret, dict);
    }
    return ret;
}

void __attribute__((constructor)) hook_lsd(void)
{
    struct mach_header_64 *header = (typeof (header))_dyld_get_image_header(0);
    const struct load_command *cmd = (typeof(cmd))(header + 1);
    const struct segment_command_64 *first = NULL;
    const struct segment_command_64 *data = NULL;
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (typeof(cmd)) ((char*) cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64) {
            if (!first && ((typeof(first))cmd)->filesize ) {
                first = (typeof(first)) cmd;
            }
    #ifndef __arm64__
            if (strcmp(((typeof(data))cmd)->segname, "__DATA") == 0) {
    #else
            if (strcmp(((typeof(data))cmd)->segname, "__DATA_CONST") == 0) {
    #endif
                data = (typeof(data))cmd;
                break;
            }
        }
    }
    uintptr_t slide = (uintptr_t)header - first->vmaddr;
    void **address = (void **)(data->vmaddr + slide);
    void **end = (void **)(data->vmaddr + data->vmsize + slide);
    while (address < end) {
    #if __arm64__
        if (((uintptr_t)*address & 0xFFFFFFFFFFF) == ((uintptr_t)(xpc_dictionary_get_int64) & 0xFFFFFFFFFFF)) {
            mprotect((void *)(((uintptr_t)address) & ~0x3FFF), 0x4000, PROT_READ | PROT_WRITE);
            *address = ptrauth_sign_unauthenticated((void *)((uintptr_t)&xpc_dictionary_get_int64_hook & 0xFFFFFFFFFFF), ptrauth_key_function_pointer, address);
        }
    #else
        if (*address == xpc_dictionary_get_int64) {
            *address = xpc_dictionary_get_int64_hook;
        }
    #endif
        address++;
    }
}
