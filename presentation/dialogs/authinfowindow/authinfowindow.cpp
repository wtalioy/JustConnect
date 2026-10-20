#include "authinfowindow.h"

#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "application/authmethodsquery.h"
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QPushButton>

AuthInfoWindow::AuthInfoWindow(QWidget *parent, CoreEngine *inputEngine)
    : QDialog(parent),
    ui(new Ui::AuthInfoWindow),
    query(new AuthMethodsQuery(inputEngine ? inputEngine : new EmbeddedCoreEngine,this))
{
    ui->setupUi(this);
    ui->label->setWordWrap(true);

    setWindowModality(Qt::WindowModal);
    setAttribute(Qt::WA_DeleteOnClose);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    connect(
        ui->authInfoListWidget,
        &QListWidget::currentItemChanged,
        this,
        [this](QListWidgetItem *current)
        {
            ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(
                queryCompleted && current != nullptr
            );
        }
    );

    connect(this, &QDialog::accepted, [&]() {
        QListWidgetItem *selectedItem = ui->authInfoListWidget->currentItem();
        if (!selectedItem)
            return;
        emit finishAuthInfo(selectedItem->data(Qt::UserRole).toJsonObject());
    });

    connect(query, &AuthMethodsQuery::ready, this, [this](const QJsonArray &methods) {
        QListWidgetItem *preferred = nullptr;
        for (const auto &value : methods) {
            const auto method = value.toObject();
            const auto type = method["type"].toString();
            auto *item = new QListWidgetItem(method["name"].toString() + " - " + type + " - " + method["domain"].toString());
            item->setData(Qt::UserRole,method);
            ui->authInfoListWidget->addItem(item);
            if (preferOAuth && type == "auth/httpsOauth2"
                && (!preferred || method["name"].toString().contains("UIS",Qt::CaseInsensitive))) preferred = item;
        }
        queryCompleted=true;
        if (preferred) ui->authInfoListWidget->setCurrentItem(preferred);
        ui->label->setText(methods.isEmpty() ? "服务器没有返回可用的认证方式。" : "请选择可用的认证方式：");
    });
    connect(query,&AuthMethodsQuery::failed,this,[this](ConnectionError error) {
        queryCompleted=false;
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        QString message;
        switch(error) {
        case ConnectionError::TLS_TRUST: message="服务器证书不受信任或地址不匹配。请检查地址、系统时间和学校 CA。"; break;
        case ConnectionError::TLS_PROTOCOL: message="TLS 协议协商失败，请检查服务器端口与 TLS 兼容性。"; break;
        case ConnectionError::NETWORK_FAILED: message="网络连接失败，请检查 DNS、网络和服务器地址。"; break;
        case ConnectionError::TIMED_OUT: message="查询超时，请检查网络后重试。"; break;
        case ConnectionError::AUTHENTICATION_CHANGED: message="认证方式已变化，请重新查询。"; break;
        default: message="获取认证方式失败，请检查服务器信息及当前连接状态后重试。"; break;
        }
        ui->label->setText(message);
    });
    connect(this,&QDialog::finished,query,&AuthMethodsQuery::stop);

}

AuthInfoWindow::~AuthInfoWindow()
{
    delete ui;
}

void AuthInfoWindow::fetchAuthInfo(const ConnectionProfile &profile, bool preferOAuth)
{
    this->preferOAuth = preferOAuth;
    queryCompleted = false;
    ui->authInfoListWidget->clear();
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    ui->label->setText("正在获取认证方式，请稍候...");
    if (!query->start(profile))
        ui->label->setText("正在查询，请稍候或关闭窗口后重试。");
}
