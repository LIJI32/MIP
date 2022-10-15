#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <pwd.h>

#include "loader.h"
#include "injector/inject/inject.h"

#define objc_collectingEnabled() (@selector(retain) == @selector(release))

static char user_data_path[USER_DATA_PATH_MAX] = "";

/* Exported so it can be used by loaded library */
const char *MIP_user_data_path(void)
{
    if (!user_data_path[0]) {
        sprintf(user_data_path, USER_DATA_ROOT "/%d", getuid());
    }
    return user_data_path;
}

// Private APIs
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t, const char *);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);

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
    }
}

static int64_t (*old_xpc_dictionary_get_int64)(xpc_object_t, const char *);
static int64_t new_xpc_dictionary_get_int64(xpc_object_t dict, const char *key)
{
    int64_t ret = old_xpc_dictionary_get_int64(dict, key);
    if (strcmp(key, "command") == 0) {
        handleClientMessageHook_common(ret, dict);
    }
    return ret;
}

static void load_launchservicesd(void)
{
    MSHookFunction(xpc_dictionary_get_int64, new_xpc_dictionary_get_int64, (void**)&old_xpc_dictionary_get_int64);
}

bool should_inject_bundle(NSBundle *tweakBundle,
                          NSString *mainExecutableName,
                          NSArray<NSString *> *globalyDisabledBundles)
{
    NSDictionary *plist = tweakBundle.infoDictionary;
    bool blacklistMode = [plist[@"MIPUseBlacklistMode"] boolValue];
    
    // Skip tweak if it is globally disabled
    if ([globalyDisabledBundles containsObject:tweakBundle.bundleIdentifier]) {
        // Not affected by blacklist mode
        return false;
    }
    
    // Skip tweak if a matching bundle is excluded
    for (NSString *entry in plist[@"MIPExcludedBundleNames"]) {
        if (CFBundleGetBundleWithIdentifier((CFStringRef)entry)) {
            // Match found; skip loading
            return false;
        }
    }
    
    // Check if process matches bundle filter
    for (NSString *entry in plist[@"MIPBundleNames"]) {
        if (CFBundleGetBundleWithIdentifier((CFStringRef)entry)) {
            // Match found; invert if blacklist mode enabled
            return !blacklistMode;
        }
    }
    
    // Check if process matches executable filter
    for (NSString *entry in plist[@"MIPExecutableNames"]) {
        if ([mainExecutableName isEqualToString:entry]) {
            // Match found; invert if blacklist mode enabled
            return !blacklistMode;
        }
    }
    
    // No match find, return true if we're in blacklist mode
    return blacklistMode;
}

static void __attribute__((constructor)) loader(void)
{
    @autoreleasepool {
        @try {
            NSDictionary *user_preferences = [NSDictionary dictionaryWithContentsOfFile:
                [@(MIP_user_data_path()) stringByAppendingPathComponent:@"settings.plist"]
            ];

            NSFileManager *fm = NSFileManager.defaultManager;
            
            NSURL *tweakBundlesURL = [NSURL fileURLWithPath:@GLOBAL_DATA_ROOT "/Bundles"];
            NSArray *tweakBundles = [fm contentsOfDirectoryAtURL:tweakBundlesURL
                                      includingPropertiesForKeys:nil
                                                         options:NSDirectoryEnumerationSkipsHiddenFiles
                                                           error:nil];
            
            char executable_path[PATH_MAX];
            uint32_t executable_path_length = sizeof(executable_path);
            _NSGetExecutablePath(executable_path, &executable_path_length);
            
            NSString *executable_name = @(executable_path).lastPathComponent;
            NSArray *disabled_bundles = user_preferences[@"MIPDisabledBundles"];
            NSLog(@"MIP: load %@", executable_name);

            if ([@"launchservicesd" isEqualToString:executable_name]) {
                load_launchservicesd();
                return;
            }
            
            // Enumerate tweak bundles and determine whether or not to load each
            for (NSURL *bundle_url in tweakBundles) {
                
                NSBundle *tweakBundle = [NSBundle bundleWithURL:bundle_url];
                bool should_inject = should_inject_bundle(tweakBundle,
                                                          executable_name,
                                                          disabled_bundles);

                if (should_inject) {
                    bool tweakSupportsGC = [tweakBundle.infoDictionary[@"MIPSupportsGC"] boolValue];
                    if (objc_collectingEnabled() && !tweakSupportsGC) {
                        // Skip loading if tweak doesn't support GC
                        NSLog(@"MIP: Bundle %@ was not loaded: %s required GC",
                              tweakBundle.bundlePath, executable_path);
                    }
                    else {
                        // Attempt loading tweak bundle
                        NSError *error = nil;
                        if (![tweakBundle loadAndReturnError:&error]) {
                            NSLog(@"MIP: Bundle %@ was not loaded: %@", tweakBundle.bundlePath, error);
                        }
                        else {
                            NSLog(@"MIP: Bundle %@ was loaded", tweakBundle.bundlePath);
                        }
                    }
                }
            }
        }
        @catch (NSException *exception) {
            NSLog(@"MIP: Aborting load due to exception: %@\n%@",
                  exception, exception.callStackSymbols);
        }
    }
}
