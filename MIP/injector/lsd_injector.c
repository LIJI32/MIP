#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/syslimits.h>

#include <loader/loader.h>
#include "inject/inject.h"
#include "hook/hook.h"
#include "hook/symbols.h"

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
        inject_to_task(task, "/usr/lib/mip/loader.dylib");
    }
}

uint64_t handleClientMessageHook_Sierra(void *this, uint64_t command, xpc_object_t dict)
{
    handleClientMessageHook_common(command, dict);
    return handleClientMessageOrig_Sierra(this, command, dict);
}

uint64_t handleClientMessageHook_HighSierra(void *this, void *session, xpc_connection_t connection, xpc_object_t dict)
{
    uint64_t command = xpc_dictionary_get_int64(dict, "command");
    handleClientMessageHook_common(command, dict);
    return handleClientMessageOrig_HighSierra(this, session, connection, dict);
}

void __attribute__((constructor)) hook_lsd(void)
{
    void *symbol = get_symbol("LSXPCClientConnection::handleClientMessage(unsigned long long, void*)");
    if (symbol) {
        handleClientMessageOrig_Sierra = hook_function(symbol, (void *) handleClientMessageHook_Sierra);
    }
    else {
        symbol = get_symbol("LSXPCClient::handleClientMessage(__LSSession*, _xpc_connection_s*, void*)");
        if (symbol) {
            handleClientMessageOrig_HighSierra = hook_function(symbol, (void *) handleClientMessageHook_HighSierra);
        }
    }
}
