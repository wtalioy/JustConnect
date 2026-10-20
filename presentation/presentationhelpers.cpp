#include "presentationhelpers.h"

#include <QApplication>
#include <QMessageBox>
#include <QPixmap>
#include <QWidget>

#include "application/applicationconstants.h"

void PresentationHelpers::showAboutDialog(QWidget *parent)
{
    QMessageBox messageBox(parent);
    messageBox.setWindowTitle("关于");
    messageBox.setTextFormat(Qt::RichText);
    const QString repository = ApplicationConstants::RepositoryName;
    messageBox.setText(
        QApplication::applicationDisplayName() + " " + QApplication::applicationVersion() +
        "<br>校园网络访问客户端" +
        "<br>维护者：<a href='https://github.com/wtalioy'>wtalioy</a>" +
        "<br>项目主页：<a href='https://github.com/" + repository +
        "'>https://github.com/" + repository + "</a>" +
        "<br>核心依赖：<a href='https://github.com/Mythologyli/zju-connect'>zju-connect</a>" +
        "<br><br>上游贡献者：" +
        "<a href='https://github.com/chenx-dust'>Chenx Dust</a>、" +
        "<a href='https://github.com/Mythologyli'>Myth</a>、" +
        "<a href='https://github.com/lyc8503'>lyc8503</a>"
    );
    messageBox.setIconPixmap(QPixmap(":/resource/icon.svg").scaled(
        100,
        100,
        Qt::KeepAspectRatio,
        Qt::SmoothTransformation
    ));
    messageBox.exec();
}

bool PresentationHelpers::confirmCredentials(
    const QString &username,
    const QString &password
)
{
    if (username.isEmpty() || password.isEmpty())
    {
        return QMessageBox::warning(
            nullptr,
            "警告",
            "账号或密码为空！\n\n是否继续？",
            QMessageBox::Ok,
            QMessageBox::Cancel
        ) == QMessageBox::Ok;
    }

    const auto containsNonAscii = [](const QString &value)
    {
        for (const QChar character : value)
        {
            if (character.unicode() > 127)
            {
                return true;
            }
        }
        return false;
    };
    if (containsNonAscii(username) || containsNonAscii(password))
    {
        return QMessageBox::warning(
            nullptr,
            "警告",
            "账号或密码存在非 ASCII 字符！\n建议检查输入法设置。\n\n是否继续？",
            QMessageBox::Ok,
            QMessageBox::Cancel
        ) == QMessageBox::Ok;
    }
    return true;
}

QString PresentationHelpers::platformOperationMessage(const PlatformOperationResult &result)
{
    using Status = PlatformOperationResult::Status;
    QString text;
    switch (result.status) {
    case Status::Success: text = "操作成功"; break;
    case Status::Failed: text = "操作失败"; break;
    case Status::Cancelled: text = "用户已取消授权"; break;
    case Status::PermissionDenied: text = "权限被拒绝"; break;
    case Status::Unsupported: text = "当前平台或桌面不支持此操作"; break;
    case Status::TimedOut: text = "操作超时"; break;
    }
    if (!result.detail.isEmpty()) text += "\n" + result.detail;
    if (result.mayHaveChanged && !result.succeeded()) text += "\n部分设置可能已修改，请检查残留设置。";
    return text;
}
