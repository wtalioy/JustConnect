#include "infrastructure/networkhelper/macos/helperregistration.h"
#include "infrastructure/networkhelper/macos/networkhelper.h"
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

PlatformOperationResult registerMacNetworkHelper()
{
    using Status = PlatformOperationResult::Status;
    @autoreleasepool {
        auto *service = [SMAppService daemonServiceWithPlistName:[NSString stringWithUTF8String:MacHelperPlist]];
        if (service.status == SMAppServiceStatusNotRegistered || service.status == SMAppServiceStatusNotFound) {
            NSError *error = nil;
            if (![service registerAndReturnError:&error])
                return {Status::PermissionDenied,QStringLiteral("Cannot register the network helper: ")+QString::fromUtf8(error.localizedDescription.UTF8String)};
        }
        if (service.status == SMAppServiceStatusRequiresApproval)
            return {Status::PermissionDenied,QStringLiteral("Approve JustConnect in System Settings > General > Login Items & Extensions, then retry.")};
        if (service.status != SMAppServiceStatusEnabled)
            return {Status::Unsupported,QStringLiteral("The signed application bundle does not contain an available network helper.")};
        return {};
    }
}
