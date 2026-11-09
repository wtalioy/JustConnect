#include "infrastructure/networkhelper/macos/networkhelperclient.h"
#include <QCoreApplication>
#import <ServiceManagement/ServiceManagement.h>
#import <objc/runtime.h>

@interface RegisteredServiceFixture : NSObject
@end

@implementation RegisteredServiceFixture
- (SMAppServiceStatus)status { return SMAppServiceStatusEnabled; }
- (void)unregisterWithCompletionHandler:(void (^)(NSError *))completion { completion(nil); }
- (BOOL)registerAndReturnError:(NSError **)error { return YES; }
@end

int checkSilentHelper(QCoreApplication &app)
{
    const auto method=class_getClassMethod(SMAppService.class,@selector(daemonServiceWithPlistName:));
    if (!method) return 1;
    const auto fixture=imp_implementationWithBlock(^id(id, NSString *) {
        return [[RegisteredServiceFixture new] autorelease];
    });
    const auto previous=method_setImplementation(method,fixture);
    MacNetworkHelperClient client;
    QObject::connect(&client,&MacNetworkHelperClient::finished,&app,[&](auto operation,auto result) {
        const bool bounded=operation==MacNetworkHelperClient::Operation::Inspect
            && result.status==PlatformOperationResult::Status::Failed && !result.mayHaveChanged && result.offerBackgroundSettings;
        app.exit(bounded ? 0 : 1);
    });
    QTimer::singleShot(12000,&app,[&] { app.exit(1); });
    QTimer::singleShot(0,&client,[&] { client.inspect(QUuid::createUuid()); });
    const int result=app.exec();
    method_setImplementation(method,previous);
    imp_removeBlock(fixture);
    return result;
}
