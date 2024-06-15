#import <Foundation/Foundation.h>

@protocol MIPProtocol
- (void)injectDylib:(const char *)dylib toPID:(pid_t)pid interruptSyscalls:(bool)interrupt withReply:(void (^)(NSString *error))reply;
@end
