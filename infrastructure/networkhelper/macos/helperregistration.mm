#include "infrastructure/networkhelper/macos/helperregistration.h"
#include "infrastructure/networkhelper/macos/networkhelper.h"
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

PlatformOperationResult registerMacNetworkHelper(bool refresh)
{
    using Status = PlatformOperationResult::Status;
    @autoreleasepool {
        auto *service = [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:MacHelperPlist]];
        auto status = service.status;
        const bool replace = refresh && status == SMAppServiceStatusEnabled;
        NSError *error = nil;
        if (replace && ![service unregisterAndReturnError:&error])
            return {Status::PermissionDenied,QStringLiteral("Cannot refresh the network helper registration: ")+QString::fromUtf8(error.localizedDescription.UTF8String)};
        if (replace || status == SMAppServiceStatusNotRegistered || status == SMAppServiceStatusNotFound) {
            const bool registered = [service registerAndReturnError:&error];
            status = service.status;
            if (!registered && status != SMAppServiceStatusRequiresApproval)
                return {Status::PermissionDenied,QStringLiteral("Cannot register the network helper: ")+QString::fromUtf8(error.localizedDescription.UTF8String)};
        }
        if (status == SMAppServiceStatusRequiresApproval)
            return {Status::PermissionDenied,QStringLiteral("Approve JustConnect in System Settings > General > Login Items & Extensions, then retry.")};
        if (status != SMAppServiceStatusEnabled)
            return {Status::Unsupported,QStringLiteral("The signed application bundle does not contain an available network helper.")};
        return {};
    }
}
