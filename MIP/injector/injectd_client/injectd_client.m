#import <Foundation/Foundation.h>
#import <pthread.h>
#import "MIPProtocol.h"

const char *inject_to_pid(pid_t pid, const char *dylib, bool interrupt_syscalls)
{
    __block NSString *ret = @"Could not connect to injectd";

    @autoreleasepool {
        static id<MIPProtocol> remoteObject = nil;
        static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
        
        
        __block bool shouldRetry = false;
        __block bool didRetry = false;
        
    retry:
        pthread_mutex_lock(&lock);
        if (!remoteObject) {
            static NSXPCConnection *connection = nil;
            if (connection) {
                [connection invalidate];
                connection = nil;
            }
            
            connection = [[NSXPCConnection alloc] initWithMachServiceName:@"local.injectd" options:0];
            connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MIPProtocol)];
            [connection resume];
            
            remoteObject = [connection synchronousRemoteObjectProxyWithErrorHandler:^(NSError *error) {
                NSLog(@"injectd connection error: %@", error.localizedDescription);
                ret = error.localizedDescription;
                if (!didRetry) {
                    shouldRetry = true;
                }
            }];
        }
        
        [remoteObject injectDylib:dylib toPID:pid interruptSyscalls:interrupt_syscalls withReply:^(NSString *reply) {
            ret = reply;
        }];
        
        pthread_mutex_unlock(&lock);
        
        if (shouldRetry) {
            shouldRetry = false;
            didRetry = true;
            remoteObject = nil;
            goto retry;
        }
    }
        
    return ret.UTF8String;
}
