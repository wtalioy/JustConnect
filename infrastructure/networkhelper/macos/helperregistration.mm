#include "infrastructure/networkhelper/macos/helperregistration.h"
#include "infrastructure/networkhelper/macos/networkhelper.h"
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <cerrno>
#include <dispatch/dispatch.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
using Completion = std::function<void(Result)>;

auto registrationQueue() { return dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0); }

Result permissionFailure(const char *operation, NSError *error, SMAppServiceStatus status)
{
    return {Status::PermissionDenied,QStringLiteral("%1: %2 (%3 %4, service status %5)")
        .arg(QString::fromLatin1(operation),QString::fromUtf8(error.localizedDescription.UTF8String),
             QString::fromUtf8(error.domain.UTF8String))
        .arg(qlonglong(error.code)).arg(qlonglong(status))};
}

void registerService(SMAppService *service, Completion completion, bool afterUnregister)
{
    auto status = service.status;
    if (afterUnregister || status == SMAppServiceStatusNotRegistered || status == SMAppServiceStatusNotFound) {
        NSError *error = nil;
        const bool registered = [service registerAndReturnError:&error];
        status = service.status;
        if (!registered && status != SMAppServiceStatusRequiresApproval) {
            // Service Management can return EPERM while a just-removed job is still retiring.
            if (afterUnregister && error.code==EPERM && [error.domain isEqualToString:@"SMAppServiceErrorDomain"]) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),registrationQueue(),^{
                    @autoreleasepool { registerService(service,completion,false); }
                });
                return;
            }
            completion(permissionFailure("Cannot register the network helper",error,status));
            return;
        }
    }
    if (status == SMAppServiceStatusRequiresApproval)
        completion({Status::PermissionDenied,QStringLiteral("Approve JustConnect in System Settings > General > Login Items & Extensions, then retry.")});
    else if (status != SMAppServiceStatusEnabled)
        completion({Status::Unsupported,QStringLiteral("The signed application bundle does not contain an available network helper.")});
    else
        completion({});
}
}

void registerMacNetworkHelper(bool refresh, std::function<void(PlatformOperationResult)> completion)
{
    dispatch_async(registrationQueue(),^{
        @autoreleasepool {
            auto *service = [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:MacHelperPlist]];
            if (!refresh || service.status != SMAppServiceStatusEnabled) {
                registerService(service,completion,false);
                return;
            }
            [service unregisterWithCompletionHandler:^(NSError *error) {
                dispatch_async(registrationQueue(),^{
                    @autoreleasepool {
                        if (error) completion(permissionFailure("Cannot refresh the network helper registration",error,service.status));
                        else registerService(service,completion,true);
                    }
                });
            }];
        }
    });
}
