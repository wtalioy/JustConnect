#include "infrastructure/networkhelper/macos/helperregistration.h"
#include <QSemaphore>
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <objc/runtime.h>
#include <atomic>
#include <cerrno>
#include <utility>

namespace {
QSemaphore unregisterStarted, allowUnregister;
std::atomic_int registrations{0};
bool requiresApproval = false;
}

@interface RegistrationFixture : NSObject
@end

@implementation RegistrationFixture {
    SMAppServiceStatus current;
}
- (instancetype)init
{
    if ((self = [super init])) current = requiresApproval ? SMAppServiceStatusRequiresApproval : SMAppServiceStatusEnabled;
    return self;
}
- (SMAppServiceStatus)status { return current; }
- (void)unregisterWithCompletionHandler:(void (^)(NSError *))completion
{
    unregisterStarted.release();
    allowUnregister.acquire();
    current = SMAppServiceStatusNotRegistered;
    completion(nil);
}
- (BOOL)registerAndReturnError:(NSError **)error
{
    if (++registrations == 1) {
        *error = [NSError errorWithDomain:@"SMAppServiceErrorDomain" code:EPERM userInfo:nil];
        return NO;
    }
    current = SMAppServiceStatusEnabled;
    return YES;
}
@end

int main()
{
    @autoreleasepool {
        const auto method = class_getClassMethod(SMAppService.class,@selector(daemonServiceWithPlistName:));
        if (!method) return 1;
        const auto fixture = imp_implementationWithBlock(^id(id, NSString *) {
            return [[RegistrationFixture new] autorelease];
        });
        const auto previous = method_setImplementation(method,fixture);
        QSemaphore finished;
        PlatformOperationResult result{PlatformOperationResult::Status::Failed};
        registerMacNetworkHelper(true,[&](PlatformOperationResult outcome) {
            result = std::move(outcome);
            finished.release();
        });
        const bool waited = unregisterStarted.tryAcquire(1,2000) && registrations == 0;
        allowUnregister.release();
        if (!finished.tryAcquire(1,5000)) return 1;
        if (!waited || !result.succeeded() || registrations != 2) return 1;
        requiresApproval = true;
        checkMacNetworkHelperApproval([&](PlatformOperationResult outcome) {
            result = std::move(outcome);
            finished.release();
        });
        if (!finished.tryAcquire(1,2000)) return 1;
        method_setImplementation(method,previous);
        imp_removeBlock(fixture);
        return result.status == PlatformOperationResult::Status::PermissionDenied
            && result.requiresBackgroundApproval && registrations == 2 ? 0 : 1;
    }
}
