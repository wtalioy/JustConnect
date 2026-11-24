#pragma once

#include <QString>
#include <QStringList>

struct UpdatePackage;

namespace UpdateInstaller {
inline constexpr auto WorkerOption = "--install-staged-update";
inline constexpr auto FailedOption = "--update-install-failed";
inline constexpr auto CleanupOption = "--remove-staged-installer";
QString assetSuffix();
bool launch(const UpdatePackage &package,const QString &path);
int installAfterExit(const QStringList &arguments);
void removeStagedInstaller(const QString &path);
}
