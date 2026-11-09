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
auto networkService() { return [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:MacHelperPlist]]; }
Result approvalRequired()
{
    return {Status::PermissionDenied,QStringLiteral("Approve JustConnect in System Settings > General > Login Items & Extensions, then retry."),false,true};
}

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
            const bool denied = error.code==EPERM && [error.domain isEqualToString:@"SMAppServiceErrorDomain"];
            // Service Management can return EPERM while a just-removed job is still retiring.
            if (afterUnregister && denied) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),registrationQueue(),^{
                    @autoreleasepool { registerService(service,completion,false); }
                });
                return;
            }
            auto result = permissionFailure("Cannot register the network helper",error,status);
            result.requiresBackgroundApproval = denied;
            completion(result);
            return;
        }
    }
    if (status == SMAppServiceStatusRequiresApproval)
        completion(approvalRequired());
    else if (status != SMAppServiceStatusEnabled)
        completion({Status::Unsupported,QStringLiteral("The signed application bundle does not contain an available network helper.")});
    else
        completion({});
}
}

void openMacBackgroundApprovalSettings()
{
    [SMAppService openSystemSettingsLoginItems];
}

void checkMacNetworkHelperApproval(std::function<void(PlatformOperationResult)> completion)
{
    dispatch_async(registrationQueue(),^{
        @autoreleasepool {
            completion(networkService().status==SMAppServiceStatusRequiresApproval ? approvalRequired() : Result{});
        }
    });
}

void registerMacNetworkHelper(bool refresh, std::function<void(PlatformOperationResult)> completion)
{
    dispatch_async(registrationQueue(),^{
        @autoreleasepool {
            auto *service = networkService();
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
