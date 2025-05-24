#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/syslimits.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include "injectd_client/injectd_client.h"

// Private APIs
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t, const char *);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);

static const char *MIP_injector_path(void)
{
    Dl_info info;
    dladdr("", &info); // Get own info
    return info.dli_fname;
}

static const char *MIP_loader_path(void)
{
    static char *ret = NULL;
    if (ret) return ret;
    
    ret = strdup(MIP_injector_path());
    *strrchr(ret, '/') = 0;
    
    // strlen("loader.dylib") < strlen("lsdinjector.dylib")
    strcat(ret, "/loader.dylib");
    
    return ret;
}

static const char *MIP_root_path(void)
{
    static char *ret = NULL;
    if (ret) return ret;
    
    ret = strdup(MIP_injector_path());
    *strrchr(ret, '/') = 0;
    return ret;
}

/* We want the user data to be accessible from all processes, but some processes (for
   example, Chrome's sub-processes) have a very strict sandbox profile so putting the
   data in the user's home folder won't always work. /usr/lib, on the other hand, is
   accessible from all processes (Otherwise they're pretty much worthless to hook in
   the first place), so we put our data in /usr/lib/mip/user_data/<uid>/. We also set
   a symlink in the user's Library folder, for easier access. */
static void create_user_data_folder(pid_t pid)
{
    struct proc_bsdinfo proc;
    proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc, sizeof(proc));
    
    char path[PATH_MAX];
    sprintf(path, "%s/user_data/%d", MIP_root_path(), proc.pbi_uid);
    
    if (mkdir(path, 0755)) return; // Might already exist
    chown(path, proc.pbi_uid, proc.pbi_gid);
    
    struct passwd *pw = getpwuid(proc.pbi_uid);
    char library_path[PATH_MAX];
    if (snprintf(library_path, sizeof(library_path), "%s/Library/MIP", pw->pw_dir) < sizeof(library_path)) {
        symlink(path, library_path);
        lchown(library_path, proc.pbi_uid, proc.pbi_gid);
    }
}

static void handleClientMessageHook_common(uint64_t command, xpc_object_t dict)
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
        inject_to_pid(pid, MIP_loader_path(), false);
    }
}

static uint64_t xpc_dictionary_get_int64_hook(xpc_object_t dict, const char *key)
{
    uint64_t ret = xpc_dictionary_get_int64(dict, key);
    if (strcmp(key, "command") == 0) {
        handleClientMessageHook_common(ret, dict);
    }
    return ret;
}

#if __arm64__

// Derived from code by khanhduytran0 {
#define _COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define _COMM_PAGE_TPRO_WRITE_ENABLE (_COMM_PAGE_START_ADDRESS + 0x0D0)
#define _COMM_PAGE_TPRO_WRITE_DISABLE (_COMM_PAGE_START_ADDRESS + 0x0D8)

static bool os_tpro_is_supported(void)
{
    if (*(uint64_t*)_COMM_PAGE_TPRO_WRITE_ENABLE) {
        return true;
    }
    return false;
}

__attribute__((naked)) bool os_thread_self_tpro_is_writeable(void)
{
    __asm__ __volatile__ (
                          "mrs             x0, s3_6_c15_c1_5\n"
                          "ubfx            x0, x0, #0x24, #1;\n"
                          "ret\n"
                          );
}

void os_thread_self_restrict_tpro_to_rw(void)
{
    __asm__ __volatile__ (
                          "mov x0, %0\n"
                          "ldr x0, [x0]\n"
                          "msr s3_6_c15_c1_5, x0\n"
                          "isb sy\n"
                          :: "r" (_COMM_PAGE_TPRO_WRITE_ENABLE)
                          : "memory", "x0"
                          );
    return;
}

void os_thread_self_restrict_tpro_to_ro(void)
{
    __asm__ __volatile__ (
                          "mov x0, %0\n"
                          "ldr x0, [x0]\n"
                          "msr s3_6_c15_c1_5, x0\n"
                          "isb sy\n"
                          :: "r" (_COMM_PAGE_TPRO_WRITE_DISABLE)
                          : "memory", "x0"
                          );
    return;
}

// }

static void unprotect_page(void *page)
{
    if (mprotect(page, 0x4000, PROT_READ | PROT_WRITE) == 0) {
        return;
    }
    void *temp = malloc(0x4000);
    memcpy(temp, page, 0x4000);
    vm_deallocate(mach_task_self(), (vm_address_t)page, 0x4000);
    vm_allocate(mach_task_self(), (vm_address_t *)&page, 0x4000, VM_FLAGS_FIXED);
    memcpy(page, temp, 0x4000);
    free(temp);
}
#endif

static void __attribute__((constructor)) hook_lsd(void)
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
#if __arm64__
    bool has_tpro = os_tpro_is_supported();
#endif
    while (address < end) {
    #if __arm64__
        if ((uintptr_t)__builtin_ptrauth_strip(*address, 0) == (uintptr_t)__builtin_ptrauth_strip(&xpc_dictionary_get_int64, 0)) {
            bool revert_tpro_state = false;
            if (!has_tpro) {
                unprotect_page((void *)(((uintptr_t)address) & ~0x3FFF));
            }
            else if (!os_thread_self_tpro_is_writeable()) {
                os_thread_self_restrict_tpro_to_rw();
                revert_tpro_state = true;
            }
            *address = ptrauth_sign_unauthenticated((void *)((uintptr_t)__builtin_ptrauth_strip(&xpc_dictionary_get_int64_hook, 0)), ptrauth_key_function_pointer, address);
            if (revert_tpro_state) {
                os_thread_self_restrict_tpro_to_ro();
            }
        }
    #else
        if (*address == xpc_dictionary_get_int64) {
            *address = xpc_dictionary_get_int64_hook;
        }
    #endif
        address++;
    }
}
