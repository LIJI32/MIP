#import <bundle/AZHSettings.h>
#import "AppDelegate.h"

@interface AppDelegate ()
@property (weak) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSPopUpButtonCell *defaultButton;
@property (weak) IBOutlet NSPopUpButton *shiftButton;
@property (weak) IBOutlet NSPopUpButton *altButton;
@property (weak) IBOutlet NSPopUpButton *commandButton;
@property (weak) IBOutlet NSPopUpButton *controlButton;
@end

@implementation AppDelegate

- (Class) getSettingsClass
{
    Class $AZHSettings = NSClassFromString(@"AZHSettings");
    if (!$AZHSettings) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:@"Alt Zoom does not appear to be installed."];
        [alert addButtonWithTitle:@"Close"];
        [alert runModal];
        [NSApp terminate:nil];
    }
    
    return $AZHSettings;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    Class $AZHSettings = [self getSettingsClass];
    
    NSDictionary *settings = [$AZHSettings settings];
    [self.defaultButton selectItemWithTag: [settings[@"Default"] intValue]];
    [self.shiftButton   selectItemWithTag: [settings[@"Shift"]   intValue]];
    [self.altButton     selectItemWithTag: [settings[@"Alt"]     intValue]];
    [self.commandButton selectItemWithTag: [settings[@"Command"] intValue]];
    [self.controlButton selectItemWithTag: [settings[@"Control"] intValue]];
}

- (IBAction)settingChanged:(NSPopUpButton *)sender
{
    Class $AZHSettings = [self getSettingsClass];
    
    NSMutableDictionary *new_settings = [[$AZHSettings settings] mutableCopy];
    new_settings[@((char *[]){
        "Default",
        "Shift",
        "Alt",
        "Command",
        "Control",
    }[sender.tag])] = @(sender.selectedTag);
    
    [$AZHSettings updateSettings:new_settings];
}

- (void)windowWillClose:(NSNotification *)notification
{
    [NSApp terminate: nil];
}
@end
