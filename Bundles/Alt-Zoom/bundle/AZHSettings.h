#import <Cocoa/Cocoa.h>

typedef enum {
    AZH_SAME_AS_DEFAULT,
    AZH_ZOOM,
    AZH_FULLSCREEN,
    AZH_MAXIMIZE,
} AZHBehavior;

@interface AZHSettings : NSObject

+ (AZHBehavior) behaviorForModifiers: (NSEventModifierFlags) modifiers;
+ (void) updateSettings: (NSDictionary *)settings;
+ (NSDictionary *)settings;

@end
