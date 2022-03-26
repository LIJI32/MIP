#import <Cocoa/Cocoa.h>
#include <objc/runtime.h>
#include "AZHSettings.h"

static bool checking_for_fullscreen = false;

/* Hook NSEvent methods to report a different status of the Alt/Option key when checking_for_fullscreen is true*/
@implementation NSEvent (AltZoomHook)

- (NSEventModifierFlags) AZH_modifierFlags
{
    NSEventModifierFlags ret = [self AZH_modifierFlags];
    
    if (checking_for_fullscreen) {
        if ([AZHSettings behaviorForModifiers:ret] == AZH_FULLSCREEN) {
            ret &= ~NSEventModifierFlagOption;
        }
        else {
            ret |= NSEventModifierFlagOption;
        }
    }
    
    return ret;
}

+ (NSEventModifierFlags) AZH_modifierFlags
{
    NSEventModifierFlags ret = [self AZH_modifierFlags];
    
    if (checking_for_fullscreen) {
        if ([AZHSettings behaviorForModifiers:ret] == AZH_FULLSCREEN) {
            ret &= ~NSEventModifierFlagOption;
        }
        else {
            ret |= NSEventModifierFlagOption;
        }
    }
    
    return ret;
}


+ (void) load
{
    method_exchangeImplementations(class_getClassMethod(self, @selector(modifierFlags)),
                                   class_getClassMethod(self, @selector(AZH_modifierFlags)));
    
    method_exchangeImplementations(class_getInstanceMethod(self, @selector(modifierFlags)),
                                   class_getInstanceMethod(self, @selector(AZH_modifierFlags)));

}
@end


/* Hook _NSThemeWidgetCell to set checking_for_fullscreen (This controls the icon drawing) */
@interface _NSThemeWidgetCell : NSCell
- (void *) coreUIWidgetType;
@end

@implementation _NSThemeWidgetCell (AltZoomHook)
- (void *) AZH_coreUIWidgetType
{
    checking_for_fullscreen = true;
    void *ret = [self AZH_coreUIWidgetType];
    checking_for_fullscreen = false;
    return ret;
}

+ (void) load
{
    method_exchangeImplementations(class_getInstanceMethod(self, @selector(coreUIWidgetType)),
                                   class_getInstanceMethod(self, @selector(AZH_coreUIWidgetType)));
    
}
@end

@interface NSWindow ()
- (void) _setNeedsZoom:(id) sender;
- (struct CGRect)_standardFrame;
@end

/* Hook NSWindow to set checking_for_fullscreen (This controls the actual action taken) */
@implementation NSWindow (AltZoomHook)
- (void) AZH__setNeedsZoom:(id) sender;
{
    checking_for_fullscreen = true;
    [self AZH__setNeedsZoom:sender];
    checking_for_fullscreen = false;
}

- (struct CGRect)AZH__standardFrame
{
    /* Disable hooking, but for modifierFlags and for application callbacks triggered by standardFrame */
    checking_for_fullscreen = false;
    
    if ([AZHSettings behaviorForModifiers:[NSEvent modifierFlags]] != AZH_MAXIMIZE) {
        return [self AZH__standardFrame];
    }
    
    id old_delegate = self.delegate;
    self.delegate = nil;
    struct CGRect ret = [self AZH__standardFrame];
    self.delegate = old_delegate;
    return ret;
}

+ (void) load
{
    method_exchangeImplementations(class_getInstanceMethod(self, @selector(_setNeedsZoom:)),
                                   class_getInstanceMethod(self, @selector(AZH__setNeedsZoom:)));
    method_exchangeImplementations(class_getInstanceMethod(self, @selector(_standardFrame)),
                                   class_getInstanceMethod(self, @selector(AZH__standardFrame)));

    
}
@end
