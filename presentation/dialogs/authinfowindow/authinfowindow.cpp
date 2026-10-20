#include "authinfowindow.h"

#include "infrastructure/coreengine/embeddedcoreengine.h"
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QPushButton>

AuthInfoWindow::AuthInfoWindow(QWidget *parent, CoreEngine *inputEngine)
    : QDialog(parent),
    ui(new Ui::AuthInfoWindow),
    engine(inputEngine ? inputEngine : new EmbeddedCoreEngine)
{
    ui->setupUi(this);

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
        emit finishAuthInfo(selectedItem->data(Qt::UserRole).toString(),
                            selectedItem->data(Qt::UserRole + 1).toString(),
                            selectedItem->data(Qt::UserRole + 2).toString());
    });

    engine->setParent(this);
    connect(engine, &CoreEngine::authMethodsReady, this, [this](const QJsonArray &methods) {
        for (const auto &value : methods) {
            const auto method = value.toObject();
            const auto type = method["type"].toString();
            auto *item = new QListWidgetItem(method["name"].toString() + " - " + type + " - " + method["domain"].toString());
            item->setData(Qt::UserRole, type);
            item->setData(Qt::UserRole + 1, method["domain"].toString());
            item->setData(Qt::UserRole + 2, method["login_url"].toString());
            ui->authInfoListWidget->addItem(item);
        }
        ui->label->setText(methods.isEmpty() ? "服务器没有返回可用的认证方式。" : "请选择可用的认证方式：");
    });
    connect(engine, &CoreEngine::finished, this, [this](ConnectionError error) {
        queryCompleted = error == ConnectionError::NONE;
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(queryCompleted && ui->authInfoListWidget->currentItem());
        if (error != ConnectionError::NONE)
            ui->label->setText("获取认证方式失败，请检查服务器信息及当前连接状态后重试。");
    });
    connect(this, &QDialog::finished, engine, &CoreEngine::stop);

}

AuthInfoWindow::~AuthInfoWindow()
{
    delete ui;
}

void AuthInfoWindow::fetchAuthInfo(const QString& serverAddress, int port)
{
    queryCompleted = false;
    ui->authInfoListWidget->clear();
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    ui->label->setText("正在获取认证方式，请稍候...");
    ConnectionProfile profile;
    profile.endpoint.protocol = "atrust";
    profile.endpoint.server = serverAddress;
    profile.endpoint.port = port;
    if (!engine->start(profile, CoreEngine::Operation::AuthMethods))
        ui->label->setText("正在查询，请稍候或关闭窗口后重试。");
}
