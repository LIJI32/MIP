#import <Foundation/Foundation.h>
#import "injectd_client/MIPProtocol.h"
#import "inject/inject.h"

@interface MIPConnection : NSObject <MIPProtocol>
@end

@implementation MIPConnection

- (void)injectDylib:(const char *)dylib toPID:(pid_t)pid interruptSyscalls:(bool)interrupt withReply:(void (^)(NSString *error))reply
{
    kern_return_t ret = KERN_SUCCESS;
    mach_port_t task = 0;

    if ((ret = task_for_pid(mach_task_self(), pid, &task))) {
        reply(@"Failed to obtain task for PID.");
        return;
    }
    
    ret = inject_to_task(task, dylib);
    if (ret) {
        reply(@"Injection failed, check Console for details.");
        return;
    }
    
    if (!interrupt) {
        reply(nil);
        return;
    }
    
    /* This interrupts blocking system calls to ensure execution. */
    mach_port_t thread;
    
    ret = get_thread_port_for_task(task, &thread);
    if (!ret) {
        ret = thread_abort(thread);
    }
    if (ret) {
        reply(@"Injection succeeded, but the injected library will only run after the main thread wakes up.");
        return;
    }

    reply(nil);
}

@end

@interface ServiceDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation ServiceDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
{
    if (newConnection.effectiveUserIdentifier != 0) {
        [newConnection invalidate];
        return false;
    }
    
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MIPProtocol)];
    MIPConnection *exportedObject = [[MIPConnection alloc] init];
    newConnection.exportedObject = exportedObject;
    
    [newConnection resume];
    return true;
}

@end

int main(int argc, const char *argv[])
{
    ServiceDelegate *delegate = [ServiceDelegate new];
    
    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"local.injectd"];
    listener.delegate = delegate;
    
    [listener resume];
    [[NSRunLoop mainRunLoop] run];
    return 0;
}
