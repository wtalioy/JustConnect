#include "ui_authinfowindow.h"
#include "presentation/coordinators/controllerselectioncoordinator.h"
#include "authinfowindow.h"

#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "application/authmethodsquery.h"
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QPushButton>
#include <QEvent>

AuthInfoWindow::AuthInfoWindow(QWidget *parent, CoreEngine *inputEngine)
    : QDialog(parent),
    ui(new Ui::AuthInfoWindow),
    query(new AuthMethodsQuery(inputEngine ? inputEngine : new EmbeddedCoreEngine,this))
{
    controllerSelection=new ControllerSelectionCoordinator(this,this);
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
        int oauthCount=0;
        for (const auto &value : methods) {
            const auto method = value.toObject();
            const auto type = method["type"].toString();
            auto *item = new QListWidgetItem(method["name"].toString().isEmpty()?type:method["name"].toString());
            item->setToolTip(type+" · "+method["domain"].toString());
            item->setData(Qt::UserRole,method);
            ui->authInfoListWidget->addItem(item);
            if (type=="auth/httpsOauth2") ++oauthCount;
            if (preferOAuth && type == "auth/httpsOauth2"
                && !preferred) preferred = item;
        }
        queryCompleted=true;
        if (preferred && oauthCount==1) ui->authInfoListWidget->setCurrentItem(preferred);
        setStatus(methods.isEmpty() ? QT_TR_NOOP("No sign-in methods are available.") : QT_TR_NOOP("Choose how to sign in."));
    });
    connect(query,&AuthMethodsQuery::failed,this,[this](ConnectionError error) {
        queryCompleted=false;
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        const char *message=nullptr;
        switch(error) {
        case ConnectionError::PERMISSION_DENIED: message=QT_TR_NOOP("Network permission was denied. Check interface access or authorization."); break;
        case ConnectionError::TLS_TRUST: message=QT_TR_NOOP("The server certificate is not trusted or does not match. Check the address, system time and campus CA."); break;
        case ConnectionError::TLS_PROTOCOL: message=QT_TR_NOOP("TLS negotiation failed. Check the server port and TLS compatibility."); break;
        case ConnectionError::NETWORK_FAILED: message=QT_TR_NOOP("Connection failed. Check DNS, connectivity and the server address."); break;
        case ConnectionError::TIMED_OUT: message=QT_TR_NOOP("The query timed out. Check your network and retry."); break;
        case ConnectionError::AUTHENTICATION_CHANGED: message=QT_TR_NOOP("Sign-in methods changed. Query them again."); break;
        default: message=QT_TR_NOOP("Could not query sign-in methods. Check the server and connection, then retry."); break;
        }
        setStatus(message);
    });
    connect(this,&QDialog::finished,query,&AuthMethodsQuery::stop);

}

AuthInfoWindow::~AuthInfoWindow()
{
    delete ui;
}

void AuthInfoWindow::fetchAuthInfo(const ConnectionProfile &profile, bool preferOAuth)
{
    const auto request=++lookup;
    this->preferOAuth = preferOAuth;
    queryCompleted = false;
    ui->authInfoListWidget->clear();
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    setStatus(QT_TR_NOOP("Loading sign-in methods…"));
    controllerSelection->choose([this,profile=ConnectionProfile(profile),request](std::optional<QString> address) mutable {
        if (request!=lookup) return;
        if (!address) {setStatus(QT_TR_NOOP("Controller selection cancelled."));return;}
        profile.behavior.controllerAddress=*address;
        if (!query->start(profile)) setStatus(QT_TR_NOOP("A query is already running. Wait or close this window and retry."));
    });
}

void AuthInfoWindow::done(int result)
{
    ++lookup;controllerSelection->cancel();
    if (query->isActive()) {
        setAttribute(Qt::WA_DeleteOnClose,false);
        connect(query,&AuthMethodsQuery::settled,this,&QObject::deleteLater,Qt::SingleShotConnection);
    }
    QDialog::done(result);
}

void AuthInfoWindow::setStatus(const char *source)
{
    statusText=source;ui->label->setText(tr(source));
}
void AuthInfoWindow::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()!=QEvent::LanguageChange) return;
    ui->retranslateUi(this);
    if (statusText) ui->label->setText(tr(statusText));
}
