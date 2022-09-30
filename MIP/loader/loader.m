#include <Foundation/Foundation.h>
#include <unistd.h>
#include <stdio.h>
#include <mach-o/dyld.h>
#include <sys/syslimits.h>
#include <dlfcn.h>

#include "loader.h"

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
