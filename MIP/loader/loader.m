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

static void __attribute__((constructor)) loader(void)
{
    @autoreleasepool {
        @try {
            NSDictionary *user_preferences = [NSKeyedUnarchiver unarchiveObjectWithData:
                                              [NSData dataWithContentsOfFile:
                                               [@(MIP_user_data_path()) stringByAppendingPathComponent:@"settings.plist"]]];

            NSFileManager *fm = [NSFileManager defaultManager];
            
            NSArray *bundles = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:@GLOBAL_DATA_ROOT "/Bundles"]
                                 includingPropertiesForKeys:nil
                                                    options:NSDirectoryEnumerationSkipsHiddenFiles
                                                      error:nil
                                ];
            
            NSString *bundle_id = [[NSBundle mainBundle] bundleIdentifier];
            char executable_path[PATH_MAX];
            uint32_t executable_path_length = sizeof(executable_path);
            _NSGetExecutablePath(executable_path, &executable_path_length);
            
            NSString *executable_name = [@(executable_path) lastPathComponent];
            NSArray *disabled_bundles = user_preferences[@"MIPDisabledBundles"];
            for (NSURL *bundle_url in bundles) {
                bool should_inject = false;
                NSBundle *bundle = [NSBundle bundleWithURL:bundle_url];
                if ([disabled_bundles containsObject:bundle.bundleIdentifier]) {
                    continue;
                }
                NSDictionary *plist = [bundle infoDictionary];
                for (NSString *possible_bundle_id in plist[@"MIPBundleNames"]) {
                    if ([bundle_id isEqualToString:possible_bundle_id]) {
                        should_inject = true;
                        break;
                    }
                }
                
                if (!should_inject) {
                    for (NSString *possible_executable_name in plist[@"MIPExecutableNames"]) {
                        if ([executable_name isEqualToString:possible_executable_name]) {
                            should_inject = true;
                            break;
                        }
                    }
                }
                
                if ([plist[@"MIPUseBlacklistMode"] boolValue]) {
                    should_inject = !should_inject;
                }
                
                if (should_inject) {
                    if (objc_collectingEnabled() && ![plist[@"MIPSupportsGC"] boolValue]) {
                        NSLog(@"MIP: Bundle %@ was not loaded: %s required GC", bundle.bundlePath, executable_path);
                    }
                    else {
                        NSError *error = nil;
                        if (![bundle loadAndReturnError:&error]) {
                            NSLog(@"MIP: Bundle %@ was not loaded: %@", bundle.bundlePath, error);
                        }
                    }
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"MIP: Aborting load due to exception: %@\n%@", exception, [exception callStackSymbols]);
        }
    }
}
