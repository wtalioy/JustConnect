#include "infrastructure/platform/autostartcommon.h"
#include <QDir>

namespace {
QString quoted(QString value) {
    value.replace("\\", "\\\\"); value.replace("\"", "\\\"");
    return '"' + value + '"';
}
}
PlatformOperationResult AutoStart::setEnabled(bool enabled) {
    return setEnabled(enabled, [](const QString &p, const QStringList &a) { return runPlatformCommand(p,a); });
}
PlatformOperationResult AutoStart::setEnabled(bool enabled, const PlatformCommandRunner &runner) {
    using Status = PlatformOperationResult::Status;
    QDir bundle(QCoreApplication::applicationDirPath()); bundle.cdUp(); bundle.cdUp();
    const auto path = bundle.absolutePath();
    if (!path.endsWith(".app")) return {Status::Unsupported, "Autostart requires an application bundle"};
    if (auto valid = AutoStartDetail::validate(path); !valid.succeeded()) return valid;
    const auto name = quoted(QCoreApplication::applicationName()), target = quoted(path);
    const auto selector = "login items whose name is " + name;
    const auto query = "tell application \"System Events\"\nreturn count of (" + selector + " and path is " + target + ")\nend tell";
    const auto inspect = runner("/usr/bin/osascript", {"-e",query});
    if (!inspect.result.succeeded()) return inspect.result;
    bool ok = false; const int count = inspect.output.toInt(&ok);
    if (!ok || count < 0) return {Status::Failed, "Invalid login item query"};
    if (!enabled && count == 0) return {};
    const auto change = "tell application \"System Events\"\n"
        "if (count of (" + selector + " and path is not " + target + ")) > 0 then error \"Login item belongs to another path\"\n"
        "delete (" + selector + " and path is " + target + ")\n"
        + (enabled ? "make login item at end with properties {name:" + name + ", path:" + target + ", hidden:false}\n" : QString()) + "end tell";
    auto result = runner("/usr/bin/osascript", {"-e",change}).result;
    if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    const auto actual = runner("/usr/bin/osascript", {"-e",query});
    if (!actual.result.succeeded()) { result = actual.result; result.mayHaveChanged = true; return result; }
    if (actual.output != (enabled ? "1" : "0")) return {Status::Failed, "Login item readback mismatch", true};
    return {Status::Success, {}, true};
}
