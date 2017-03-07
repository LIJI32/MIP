#import <Cocoa/Cocoa.h>
#include <mip/loader.h>
#import "AZHSettings.h"

NSString *plist_location = nil;
NSDictionary *settings = nil;

@implementation AZHSettings

+ (AZHBehavior) _behaviorForModifiers: (NSEventModifierFlags) modifiers
{
    switch (modifiers & (NSEventModifierFlagShift | NSEventModifierFlagControl | NSEventModifierFlagOption | NSEventModifierFlagCommand)) {
        case NSEventModifierFlagShift:
            return [[settings objectForKey:@"Shift"] intValue];
            
        case NSEventModifierFlagControl:
            return [[settings objectForKey:@"Control"] intValue];
            
        case NSEventModifierFlagOption:
            return [[settings objectForKey:@"Alt"] intValue];
        
        case NSEventModifierFlagCommand:
            return [[settings objectForKey:@"Command"] intValue];
            
        default:
            return [[settings objectForKey:@"Default"] intValue];
    }
}

+ (AZHBehavior) behaviorForModifiers: (NSEventModifierFlags) modifiers
{
    AZHBehavior ret = [self _behaviorForModifiers:modifiers];
    if (ret == AZH_SAME_AS_DEFAULT) {
        return [self _behaviorForModifiers:0];
    }
    return ret;
}

+ (void) reloadSettings
{
    settings = [NSDictionary dictionaryWithContentsOfFile:plist_location];
    if (!settings) {
        settings = @{
                     @"Default": @(AZH_FULLSCREEN),
                     @"Alt": @(AZH_ZOOM),
                     };
    }
}

+ (void) updateSettings: (NSDictionary *)settings
{
    [settings writeToFile:plist_location atomically:YES];
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:@"AZHSettingsUpdated" object:nil];
}

+ (void) load
{
    plist_location = [[@(MIP_user_data_path())
                      stringByAppendingPathComponent:[[NSBundle bundleForClass:self] bundleIdentifier]]
                      stringByAppendingPathExtension:@"plist"];
    [[NSDistributedNotificationCenter defaultCenter] addObserver:self
                                                        selector:@selector(reloadSettings)
                                                            name:@"AZHSettingsUpdated"
                                                          object:nil];
    [self reloadSettings];
}

+ (NSDictionary *)settings
{
    return settings;
}

@end
