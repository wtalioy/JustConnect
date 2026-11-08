#include <algorithm>
#include "presentation/browser/signinbrowser.h"
#include "presentation/presentationhelpers.h"
#include "presentation/main/mainwindow.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/dialogs/loginwindow/loginwindow.h"
#include "presentation/dialogs/graphcaptchawindow/graphcaptchawindow.h"
#include "presentation/dialogs/ssologinwebview/ssologinwebview.h"
#include "presentation/dialogs/networkpolicywindow.h"
#include "application/applicationlogger.h"
#include "application/defaultsettings.h"
#include "tests/credentialstorefixture.h"
#include "tests/uiwait.h"
#include "presentation/widgets/serversettingswidget.h"
#include "infrastructure/process/terminationrequests.h"
#include "infrastructure/logging/applicationlogfile.h"
#include "infrastructure/settings/savedconnectionstore.h"

#include <QApplication>
#include <QAction>
#include <QAccessible>
#include <QActionGroup>
#include <QMenu>
#include <QDir>
#include <QEvent>
#include <QElapsedTimer>
#include <QKeySequence>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QInputDialog>
#include <QTabWidget>
#include <QTreeWidget>
#include <QStackedWidget>
#include <QScrollArea>
#include <QScrollBar>
#include <QToolButton>
#include <QMessageBox>
#include <QTcpServer>
#include <QLabel>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QThread>
#include <QProcess>
#include <QClipboard>
#include <QBuffer>
#include <QCheckBox>
#include <QLineEdit>
#include <QKeyEvent>
#include <QTcpSocket>
#include <QStyleHints>
#include <QStyle>
#include <QStyleOption>
#include <QLocale>
#include <QFile>
#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
#include <QUuid>
#include <cstdlib>
#include <iostream>

static void check(bool ok,const char *message) {
    if (!ok) {std::cerr << message << '\n';std::exit(1);}
}
class RecoveryNetwork : public NetworkAccess {
public:
    QUuid attempt;
    void prepare(const QUuid &id) override {attempt=id;}
    void activate(const QUuid &,const ConnectionOptions &) override {}
    void stop(const QUuid &) override {}
};
static void recoveryStatus(ApplicationLogger &logger,ApplicationLogFile &log) {
    MainWindow window(&logger,&log,nullptr,[](CoreEngine *,NetworkPolicySession *) -> NetworkAccess * {return new RecoveryNetwork;});
    auto *session=window.findChild<ConnectionSession *>();auto *network=static_cast<RecoveryNetwork *>(session->findChild<NetworkAccess *>());
    check(session->start({},{}),"start isolated network recovery presentation");
    emit network->prepared(network->attempt,{PlatformOperationResult::Status::Failed,"fixture preparation failure",false});
    emit network->stopped(network->attempt,{PlatformOperationResult::Status::TimedOut,"fixture recovery timeout",true});
    auto *title=window.findChild<QLabel *>("statusTitleLabel");
    check(title->text()=="Recovery incomplete" && session->isActive(),"unconfirmed recovery remains visible and active");
    const auto accessible=QAccessible::queryAccessibleInterface(title);
    check(accessible && accessible->text(QAccessible::Name)==title->text(),
        "a screen reader receives the actual incomplete-recovery state");
    session->stop();
    bool errorShown=false;QTimer acknowledgeError;
    QObject::connect(&acknowledgeError,&QTimer::timeout,&window,[&]{
        for(auto *widget:QApplication::topLevelWidgets())if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()){
            errorShown=true;box->accept();
        }
    });acknowledgeError.start(1);
    emit network->stopped(network->attempt,{});acknowledgeError.stop();
    check(!session->isActive() && session->state()==ConnectionState::Failed && errorShown
        && title->text()=="Disconnected","confirmed recovery distinguishes released capture from its retained earlier error");
    check(accessible->text(QAccessible::Name)==title->text(),"the accessible state follows confirmed recovery");
}
static void profileMenusKeepTheirActions(MainWindow &window,const QString &profile) {
    auto *menuButton=window.findChild<QToolButton *>("profileMenuButton");
    auto *menu=menuButton->menu();
    auto *menuBarProfiles=window.findChild<QMenu *>("profileMenu");
    auto *tray=window.findChild<QSystemTrayIcon *>();
    QMenu *trayMenu=nullptr;
    for (auto *action:tray->contextMenu()->actions()) if (action->menu()) trayMenu=action->menu();
    check(menu && trayMenu && menuBarProfiles && menu!=menuBarProfiles,
        "home, tray and native menu bar use separate profile menus");
    auto *editAction=window.findChild<QAction *>("settingAction");
    auto *addAction=window.findChild<QAction *>("addConnectionAction");
    check(menu->actions().contains(editAction) && menu->actions().contains(addAction)
        && menuBarProfiles->actions().contains(editAction) && menuBarProfiles->actions().contains(addAction),
        "the home and native profile menus expose the same edit and add actions");
    editAction->trigger();
    auto *editor=window.findChild<SettingWindow *>();
    check(editor && editor->isVisible(),"edit control opens the active profile");
    auto *scroll=editor->findChild<QScrollArea *>("loginTab");
    auto *dns=editor->findChild<QPlainTextEdit *>("domainDnsRulesEdit");
    check(scroll && dns && scroll->isAncestorOf(dns) && !editor->findChild<QComboBox *>("languageComboBox"),"profile editing contains connection fields and no application preferences");
    check(dns->isVisibleTo(editor),"domain DNS is directly available on the connection page");
    editor->reject();
    QApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    const auto checked=[](QMenu *menu) {
        QString result;
        for (auto *action:menu->actions()) if (action->isCheckable() && action->isChecked()) {
            check(result.isEmpty(),"profile selection remains exclusive");result=action->text();
        }
        return result;
    };
    const auto initial=checked(menu);
    check(!initial.isEmpty() && checked(trayMenu)==initial && checked(menuBarProfiles)==initial,
        "profile menus start with the same selection");
    SavedConnectionStore storage;
    QSettings defaultProfile(storage.connectionPath(""),QSettings::IniFormat);
    defaultProfile.setValue("JustConnect/ConnectionKind","Fudan");
    defaultProfile.setValue("JustConnect/ServerAddress","vpn.fudan.edu.cn");defaultProfile.sync();
    QSettings namedProfile(storage.connectionPath(profile),QSettings::IniFormat);
    namedProfile.setValue("JustConnect/ConnectionKind","Custom");
    namedProfile.setValue("JustConnect/ServerAddress","vpn.other-campus.invalid");namedProfile.sync();
    const auto groups=window.findChildren<QActionGroup *>().size();
    const auto homeActions = menu->actions();
    const auto trayActions = trayMenu->actions();
    const auto menuBarActions = menuBarProfiles->actions();
    for (int i=0;i<10;++i) for (const auto &name:QStringList{profile,initial}) {
        auto *source=i%2?trayMenu:menu;
        QAction *choice=nullptr;
        for (auto *action:source->actions()) if (action->isCheckable() && action->text()==name) choice=action;
        check(choice,"target profile is present after rebuilding the menu");
        choice->trigger();
        check(checked(menu)==name && checked(trayMenu)==name && checked(menuBarProfiles)==name,
            "home, tray and native profile selections stay synchronized");
        check(menuButton->text()==name && menuButton->toolTip().contains(
            name==profile ? "vpn.other-campus.invalid" : "vpn.fudan.edu.cn"),
            "home shows the selected connection name and its tooltip shows the server address");
        const auto accessible=QAccessible::queryAccessibleInterface(menuButton);
        check(accessible && accessible->text(QAccessible::Name).contains(name),
            "the current preset or server is also available to a screen reader");
        check(window.findChildren<QActionGroup *>().size()==groups
            && menu->actions()==homeActions && trayMenu->actions()==trayActions && menuBarProfiles->actions()==menuBarActions,
            "switching between existing profiles preserves all menu actions and groups");
    }
    const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if (!report.isEmpty()) check(window.grab().save(QDir(report).filePath("home-configured.png")),"save the configured preset identity on the actual home");
    QTimer::singleShot(0,&window,[&] {
        auto *name=qobject_cast<QInputDialog *>(QApplication::activeModalWidget());
        check(name,"add control asks for the profile name");
        name->setTextValue("direct-add");
        name->accept();
    });
    addAction->trigger();
    auto *created=window.findChild<SettingWindow *>();
    check(created && created->isVisible() && checked(menu)=="direct-add" && checked(trayMenu)=="direct-add"
        && !created->findChild<QComboBox *>("languageComboBox"),
        "adding a connection opens its own editor directly");
    check(created->findChild<QLineEdit *>("serverAddressLineEdit")->text().isEmpty()
        && created->findChild<QLineEdit *>("usernameLineEdit")->text().isEmpty()
        && created->findChild<QComboBox *>("authTypeComboBox")->currentData().toString().isEmpty()
        && created->findChild<QPlainTextEdit *>("domainDnsRulesEdit")->toPlainText().isEmpty(),
        "a new connection starts blank even when added from Fudan");
    created->reject();
}

class ScrollPaints final : public QObject {
public:
    explicit ScrollPaints(QString name) : name(std::move(name)) { qApp->installEventFilter(this); }
    QList<int> offsets;
    bool barPainted = false;
protected:
    bool eventFilter(QObject *target, QEvent *event) override {
        if (event->type() != QEvent::Paint) return false;
        auto *dialog = qobject_cast<QDialog *>(target);
        auto *area = dialog ? dialog->findChild<QScrollArea *>(name) : nullptr;
        if (area && area->isVisible()) {
            auto *bar = area->verticalScrollBar();
            offsets.append(bar->value());
            barPainted |= bar->isVisible();
        }
        return false;
    }
private:
    QString name;
};

static void changeLanguageFromSettings(MainWindow &window,const QString &language) {
    window.findChild<QAction *>("preferencesAction")->trigger();
    auto *dialog=window.findChild<QDialog *>("applicationSettingsDialog");
    auto *choice=dialog->findChild<QComboBox *>("languageComboBox");
    check(choice && choice->findData(language)>=0,"settings expose the requested language");
    QCoreApplication::processEvents();QCoreApplication::sendPostedEvents(nullptr,QEvent::LayoutRequest);QCoreApplication::processEvents();
    const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if (!report.isEmpty()) {
        auto *viewport=dialog->findChild<QScrollArea *>()->viewport();
        auto *behavior=dialog->findChild<QComboBox *>("closeBehaviorComboBox");
        check(choice->width()<behavior->width() && behavior->width()<=behavior->sizeHint().width(),
            "application preference dropdowns use their content width instead of filling the column");
        QLabel *languageLabel=nullptr;
        for (auto *label:dialog->findChildren<QLabel *>()) if (label->buddy()==choice) languageLabel=label;
        check(languageLabel && languageLabel->mapTo(viewport,QPoint()).x()<=4,
            "the compact fields keep their labels aligned with the left edge of the settings page");
        auto *controller=dialog->findChild<QPushButton *>("controllerSettingsButton");
        check(viewport->rect().contains(QRect(controller->mapTo(viewport,QPoint()),controller->size())),
            "the default native settings size exposes the complete Clash chooser");
        check(dialog->grab().save(QDir(report).filePath("settings-"+ApplicationLanguage::instance().current()+".png")),"save native preferences screenshot");
        choice->showPopup();UiWait::until(__FILE__,__LINE__,[&]{return choice->view()->isVisible();});
        check(choice->view()->window()->grab().save(QDir(report).filePath("dropdown-"+ApplicationLanguage::instance().current()+".png")),
            "save the actual dropdown panel and selected item");choice->hidePopup();
    }
    check(!dialog->findChild<QLineEdit *>("serverAddressLineEdit") && !qobject_cast<SettingWindow *>(dialog),"the settings shortcut opens application preferences without connection fields");
    choice->setCurrentIndex(choice->findData(language));
    QCoreApplication::processEvents();
    const auto close=dialog->findChild<QDialogButtonBox *>("applicationSettingsButtons")->button(QDialogButtonBox::Close)->text().remove('&');
    check(dialog->windowTitle()==(language=="zh_CN"?QString::fromUtf8("应用设置"):QString("App settings"))
        && close.contains(language=="zh_CN"?QString::fromUtf8("关闭"):QString("Close"))
        && !close.contains(language=="zh_CN"?QString("Close"):QString::fromUtf8("关闭")),
        "the application title and Qt standard close action use the selected language together");
    dialog->findChild<QDialogButtonBox *>("applicationSettingsButtons")->button(QDialogButtonBox::Close)->click();
    QCoreApplication::processEvents();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    check(!window.findChild<QDialog *>("applicationSettingsDialog"),"closing application settings releases its independent dialog");
}
static void languagePreferences(MainWindow &window) {
    auto *action=window.findChild<QPushButton *>("connectButton");
    check(SavedConnectionStore().language()=="en" && ApplicationLanguage::instance().current()=="en" && action->text()=="Connect","a fresh application defaults to English");
    changeLanguageFromSettings(window,"zh_CN");
    check(ApplicationLanguage::instance().current()=="zh_CN" && SavedConnectionStore().language()=="zh_CN" && action->text()==QString::fromUtf8("连接")
        && window.findChild<QSystemTrayIcon *>()->toolTip().contains(QString::fromUtf8("尚未连接")),"saving Chinese updates the existing main window and tray without recreating them");
    window.findChild<QPushButton *>("detailsButton")->click();
    auto *details=window.findChild<QDialog *>("detailsDialog");
    auto *copy=window.findChild<QPushButton *>("copyDiagnosticsButton");
    auto *refresh=window.findChild<QPushButton *>("refreshDiagnosticsButton");
    auto *rules=window.findChild<QPushButton *>("diagnosticRulesButton");
    check(copy->x()>refresh->x() && copy->x()-refresh->geometry().right()<=9 && rules->x()>copy->x(),
        "refresh and copy form one compact icon group before the rules action");
    for (const qreal ratio:{1.0,1.5,2.0}) {
        const auto glyph=rules->icon().pixmap(rules->iconSize(),ratio).toImage();
        check(!glyph.isNull(),"the spaced button icon renders at every supported test scale");
        bool hasInk=false;
        for (int x=0;x<glyph.width();++x) for (int y=0;y<glyph.height();++y)
            hasInk|=glyph.pixelColor(x,y).alpha()>0;
        check(hasInk,"the gap check also observes a visible icon");
        for (int x=glyph.width()-qRound(4*glyph.devicePixelRatio());x<glyph.width();++x)
            for (int y=0;y<glyph.height();++y)
                check(glyph.pixelColor(x,y).alpha()==0,"text buttons reserve a consistent gap after the vector icon");
    }
    check(copy->text().isEmpty() && copy->toolTip()==QCoreApplication::translate("MainWindow","Copy diagnostics")
        && copy->accessibleName()==copy->toolTip() && !copy->icon().pixmap(18,18).isNull(),
        "icon actions retain translated hover text, accessibility and a rendered glyph");
    check(details->isVisible() && details->windowTitle()==QString::fromUtf8("连接详情")
        && window.findChild<QAction *>("checkUpdateAction")->toolTip().contains(QString::fromUtf8("已禁用"))
        && window.findChild<QTreeWidget *>("diagnosticReport")->topLevelItem(2)->text(0)==QString::fromUtf8("解析来源"),
        "subsequent details and update status use the selected language without a network check");
    changeLanguageFromSettings(window,"en");
    check(details->isVisible() && details->windowTitle()=="Connection details" && action->text()=="Connect"
        && window.findChild<QAction *>("checkUpdateAction")->toolTip().contains("Disabled")
        && window.findChild<QTreeWidget *>("diagnosticReport")->topLevelItem(2)->text(0)=="DNS sources","switching back updates an already open details window");
    details->reject();
}

#define waitForUi(...) UiWait::until(__FILE__,__LINE__,__VA_ARGS__)
static void authenticationLanguageChangesPreserveData(MainWindow &window) {
    const auto screenshot=[](QWidget *widget,const QString &name) {
        const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
        if (!report.isEmpty()) check(widget->grab().save(QDir(report).filePath(name)),"save synthetic native authentication UI screenshot");
    };
    const auto language=[](const QString &next) {
        check(ApplicationLanguage::instance().savePreferences(next,SavedConnectionStore().closeToTray()),"save the active authentication language");
        QCoreApplication::processEvents();
        QCoreApplication::sendPostedEvents(nullptr,QEvent::LayoutRequest);
        QCoreApplication::processEvents();
    };
    auto *dialogs=window.findChild<AuthDialogCoordinator *>();dialogs->requestLogin("alice","typed-password");
    auto *login=window.findChild<LoginWindow *>();auto *remember=login->findChild<QCheckBox *>("saveLoginDetailCheckBox");remember->setChecked(true);
    language("zh_CN");
    check(login->windowTitle()==QString::fromUtf8("登录") && login->findChild<QLineEdit *>("usernameLineEdit")->text()=="alice"
        && login->findChild<QLineEdit *>("passwordLineEdit")->text()=="typed-password" && remember->isChecked(),"language switching preserves login input and consent");
    screenshot(login,"sign-in.png");
    auto *passwordField=login->findChild<QLineEdit *>("passwordLineEdit");
    auto *visibility=passwordField->findChild<QAction *>("visibilityAction");
    const auto concealed=visibility->icon().pixmap(18,18).toImage();visibility->trigger();
    const auto revealed=visibility->icon().pixmap(18,18).toImage();
    check(passwordField->echoMode()==QLineEdit::Normal && passwordField->text()=="typed-password"
        && !concealed.isNull() && !revealed.isNull() && revealed!=concealed,
        "the trailing eye toggles the rendered glyph and visibility without changing the password");
    visibility->trigger();check(passwordField->echoMode()==QLineEdit::Password,"the trailing eye conceals the password again");
    passwordField->setFocus();waitForUi([&]{return QApplication::focusWidget()==passwordField;});
    const auto toggleFromKeyboard=[&] {
        QKeyEvent key(QEvent::KeyPress,Qt::Key_H,Qt::ControlModifier|Qt::ShiftModifier);
        QApplication::sendEvent(passwordField,&key);
    };
    toggleFromKeyboard();check(passwordField->echoMode()==QLineEdit::Normal,"the eye action remains available from the focused field's keyboard shortcut");
    toggleFromKeyboard();check(passwordField->echoMode()==QLineEdit::Password,"the same shortcut conceals the password");
    auto *signIn=login->findChild<QDialogButtonBox *>("buttonBox")->button(QDialogButtonBox::Ok);
    int submissions=0;QString submittedAccount,submittedPassword;
    QObject::connect(login,&LoginWindow::login,login,[&](const QString &account,const QString &password,bool) {
        ++submissions;submittedAccount=account;submittedPassword=password;
    });
    login->findChild<QLineEdit *>("passwordLineEdit")->clear();signIn->click();
    check(!signIn->isEnabled() && submissions==0 && login->isVisible(),"empty credentials cannot submit or open another confirmation dialog");
    login->setDetail({},"nonempty");signIn->click();
    check(!signIn->isEnabled() && submissions==0,"an empty account also keeps sign-in disabled");
    const auto unicodeAccount=QString::fromUtf8("测试用户"),unicodePassword=QString::fromUtf8("päss word");
    login->setDetail(unicodeAccount,unicodePassword);signIn->click();
    check(submissions==1 && submittedAccount==unicodeAccount && submittedPassword==unicodePassword,
        "Unicode credentials submit once without a character-set warning or input rewriting");
    dialogs->closeCredentialPrompts();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    dialogs->requestAuthentication({{"generation","1"},{"request_id","1"},{"challenge",QJsonObject{{"kind","sms"},{"can_skip_secondary_auth",true}}}},{});
    auto *code=window.findChild<QLineEdit *>("authCodeEdit");auto *skip=window.findChild<QCheckBox *>("skipSecondaryAuthCheckBox");code->setText("654321");skip->setChecked(true);
    language("en");
    check(code->text()=="654321" && skip->isChecked() && code->window()->windowTitle()=="SMS code","active MFA translation preserves the code, choices and challenge window");
    for (auto *button:code->window()->findChildren<QPushButton *>()) {
        QStyleOptionButton option;option.initFrom(button);
        const auto contents=button->style()->subElementRect(QStyle::SE_PushButtonContents,&option,button);
        auto text=button->text();text.remove('&');
        check(contents.width()>=button->fontMetrics().horizontalAdvance(text),"translated verification buttons keep their labels inside the padded content area");
    }
    screenshot(code->window(),"verification.png");
    dialogs->closeAuthentication();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    QPixmap image(40,24);image.fill(Qt::white);QByteArray png;QBuffer buffer(&png);check(buffer.open(QIODevice::WriteOnly) && image.save(&buffer,"PNG"),"prepare a bounded captcha fixture");
    auto *captcha=new GraphCaptchaWindow(&window);captcha->setGraph(png,true);captcha->show();captcha->findChild<QLineEdit *>("codeEdit")->setText("typed-code");
    language("zh_CN");
    check(captcha->windowTitle()==QString::fromUtf8("图形验证码") && captcha->findChild<QLineEdit *>("codeEdit")->text()=="typed-code","captcha translation never reloads the image or clears entered text");
    screenshot(captcha,"captcha.png");
    captcha->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);language("en");
    QTcpServer page;check(page.listen(QHostAddress::LocalHost),"listen on a temporary local sign-in fixture");
    QObject::connect(&page,&QTcpServer::newConnection,&page,[&] {
        while (auto *socket=page.nextPendingConnection()) {
            QObject::connect(socket,&QTcpSocket::readyRead,socket,[socket] {
                socket->readAll();const QByteArray html="<!doctype html><input id='typed' value='typed-value'>";
                socket->write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: "+QByteArray::number(html.size())+"\r\n\r\n"+html);socket->disconnectFromHost();
            });
            QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
        }
    });
    const auto origin="http://127.0.0.1:"+QString::number(page.serverPort());
    auto *browser=new SsoLoginWebView(&window,QUrl(origin+"/passport/v1/auth/httpsOauth2"));browser->show();
    auto *view=browser->findChild<SignInBrowser *>();int loads=0;bool loaded=false;
    QObject::connect(view,&SignInBrowser::loadStarted,view,[&]{++loads;});
    QObject::connect(view,&SignInBrowser::loadFinished,view,[&](bool okay){check(okay,"load local browser translation fixture");loaded=true;});
    browser->setInitialUrl(QUrl(origin+"/page"));waitForUi([&]{return loaded;},UiWait::BrowserStartupTimeoutMs);language("zh_CN");language("en");
    bool read=false;QString text;view->runJavaScript("document.querySelector('#typed').value",[&](const QVariant &value){text=value.toString();read=true;});waitForUi([&]{return read;});
    check(text=="typed-value" && loads==1 && browser->windowTitle()=="Server sign-in","language switching preserves the preset page without reloading it");
    screenshot(browser,"server-sign-in.png");
    browser->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
}

static void profileSetupLanguageChangesPreserveData(MainWindow &window) {
    QTimer unexpectedMessage;
    QObject::connect(&unexpectedMessage,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            std::cerr<<"Unexpected profile translation message: "<<box->text().toStdString()<<'\n';std::exit(1);
        }
    });unexpectedMessage.start(10);
    QTemporaryDir directory;QSettings settings(directory.filePath("profile.ini"),QSettings::IniFormat);
    DefaultSettings::reset(settings);
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");
    settings.setValue("JustConnect/AuthID","opaque-method");
    settings.setValue("JustConnect/AllowUnverifiedNodes",true);
    CredentialAccess access(std::make_unique<MemoryCredentialStore>());
    const auto language=[&](const QString &value) {
        check(ApplicationLanguage::instance().savePreferences(value,SavedConnectionStore().closeToTray()),"change language with a profile draft open");
        QCoreApplication::processEvents();QCoreApplication::sendPostedEvents(nullptr,QEvent::LayoutRequest);QCoreApplication::processEvents();
    };
    language("en");
    QPointer<SettingWindow> editor=new SettingWindow(&window,&access,CredentialAccess::source(settings,{}));
    editor->show();waitForUi([&]{return !access.isBusy(settings.fileName());});
    auto *scroll=editor->findChild<QScrollArea *>("loginTab");
    auto *user=editor->findChild<QLineEdit *>("usernameLineEdit");
    auto *secret=editor->findChild<QLineEdit *>("passwordLineEdit");
    auto *method=editor->findChild<QComboBox *>("authTypeComboBox");
    auto *show=secret->findChild<QAction *>("visibilityAction");
    const auto visibilityActions=secret->actions().size();
    const auto checkColumns=[&] {
        const auto originalSize=editor->size();editor->resize(800,originalSize.height());
        QCoreApplication::processEvents();QCoreApplication::sendPostedEvents(nullptr,QEvent::LayoutRequest);QCoreApplication::processEvents();
        auto *address=editor->findChild<QLineEdit *>("serverAddressLineEdit");
        check(address->mapTo(editor,QPoint()).x()==method->mapTo(editor,QPoint()).x()
            && method->mapTo(editor,QPoint()).x()==user->mapTo(editor,QPoint()).x(),
            "address, authentication and credential fields share a column across settings groups");
        editor->resize(originalSize);QCoreApplication::processEvents();
    };
    checkColumns();
    auto *key=editor->findChild<QLineEdit *>("totpSecretLineEdit");
    auto *keyVisibility=key->findChild<QAction *>("visibilityAction");keyVisibility->trigger();
    check(key->echoMode()==QLineEdit::Normal && secret->echoMode()==QLineEdit::Password,"password and authenticator-key visibility are independent");
    keyVisibility->trigger();
    user->setText("editor-user");secret->setText("editor-password");show->setChecked(true);
    editor->findChild<QPlainTextEdit *>("domainDnsRulesEdit")->setPlainText("service.example.invalid");
    const auto methodValue=method->currentData();auto *currentContent=scroll->widget();
    language("zh_CN");
    checkColumns();
    check(secret->actions().size()==visibilityActions && show->text()==QString::fromUtf8("隐藏")
        && !show->shortcut().isEmpty() && !secret->accessibleDescription().isEmpty(),
        "language changes keep one trailing visibility action, its state and keyboard description");
    check(editor->windowTitle()==QString::fromUtf8("连接配置") && scroll->widget()==currentContent
        && !editor->findChild<QComboBox *>("languageComboBox")
        && editor->findChild<QPushButton *>("saveProfileButton")->text()==QString::fromUtf8("保存")
        && editor->findChild<QPushButton *>("dismissSettingsButton")->text()==QString::fromUtf8("取消")
        && method->currentData()==methodValue && editor->findChild<QPlainTextEdit *>("domainDnsRulesEdit")->toPlainText()=="service.example.invalid" && secret->text()=="editor-password"
        && user->text()=="editor-user" && show->isChecked() && secret->echoMode()==QLineEdit::Normal,
        "profile editor translation preserves its tab, method identity, probe target and secret draft");
    const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if(!report.isEmpty())check(editor->grab().save(QDir(report).filePath("profile-editor.png")),"save synthetic native profile editor screenshot");
    language("en");
    editor->findChild<QPushButton *>("saveProfileButton")->click();
    waitForUi([&]{return !editor || !editor->isSaving();});
    check(settings.value("JustConnect/AuthID")=="opaque-method" && settings.value("Credential/Username")=="editor-user"
        && settings.value(DefaultSettings::DomainDnsRules)=="service.example.invalid",
        "saving a translated draft preserves the opaque authentication identity and actual field values");
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
}

static void nativeHome(MainWindow &window, ApplicationLogger &logger) {
    auto *details=window.findChild<QDialog *>("detailsDialog");
    auto *log=window.findChild<QPlainTextEdit *>("logPlainTextEdit");
    auto *session=window.findChild<ConnectionSession *>();
    const auto state=session->state();
    auto *tray=window.findChild<QSystemTrayIcon *>();
    const auto mark=QIcon(":/resource/icon.svg").pixmap(24,24).toImage();
    check(!mark.isNull() && tray->icon().pixmap(24,24).toImage()==mark
        && window.windowIcon().pixmap(24,24).toImage()==mark,
        "the disconnected tray and window render the same link artwork");
    auto *appMenu=window.findChild<QToolButton *>("applicationMenuButton")->menu();
    auto *connections=window.findChild<QToolButton *>("profileMenuButton")->menu();
    check(appMenu->actions().contains(window.findChild<QAction *>("exitAction"))
        && appMenu->actions().contains(window.findChild<QAction *>("aboutAction"))
        && appMenu->actions().contains(window.findChild<QAction *>("checkUpdateAction"))
        && connections->actions().contains(window.findChild<QAction *>("clearAuthenticationCacheAction"))
        && connections->actions().contains(window.findChild<QAction *>("clearClientDataAction")),
        "application and connection actions are accessible directly from home");
    const auto connectionActions = connections->actions();
    check(connectionActions.first()->isChecked()
        && connectionActions.first()->text()=="Fudan"
        && std::none_of(connectionActions.cbegin(), connectionActions.cend(), [](QAction *action) { return action->menu(); }),
        "the selected Fudan connection appears first and every management action is directly reachable");
    check(details && details->isWindow() && !details->isVisible() && !log->isVisible(),"home keeps diagnostics in a separate closed native dialog");
    check(!window.findChild<QLabel *>("applicationNameLabel") && !window.windowIcon().isNull(),"branding appears once in the native window frame");
    check(window.findChild<QPushButton *>("connectButton")->isVisible() && qApp->styleHints()->colorScheme()!=Qt::ColorScheme::Dark,
        "redesigned home retains one accessible main action and the light appearance");
    window.findChild<QPushButton *>("detailsButton")->click();QCoreApplication::processEvents();
    check(details->isVisible() && !log->isVisible() && session->state()==state,"details opens its overview without exposing the live log or changing the session");
    check(!window.testAttribute(Qt::WA_TranslucentBackground)
        && !details->testAttribute(Qt::WA_TranslucentBackground)
        && window.grab().toImage().pixelColor(8,8).alpha()==255,
        "home and details have opaque surfaces");
    auto *reportView=details->findChild<QTreeWidget *>("diagnosticReport");
    check(!reportView->hasFocus() && !details->findChild<QLabel *>("versionLabel"),
        "overview opens without a focused diagnostics cell or version footer");
    auto *detailTabs=details->findChild<QTabWidget *>("detailsTabs");
    check(detailTabs && detailTabs->count()==2 && !details->findChild<QPushButton *>("proxyButton"),"details separates overview and logs and has no manual proxy action");
    window.findChild<QPushButton *>("copyDiagnosticsButton")->click();
    check(QApplication::clipboard()->text().contains("DNS sources: Unknown") && !window.findChild<QPushButton *>("refreshDiagnosticsButton")->isEnabled(),
        "offline diagnostics copy real unknown states and do not offer network refresh");
    window.findChild<QPushButton *>("diagnosticRulesButton")->click();
    auto *rules=window.findChild<NetworkPolicyWindow *>();
    check(rules && rules->isVisible(),"diagnostics reuse the original policy and DNS detail window");
    rules->close();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    const auto detailsReport=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if (!detailsReport.isEmpty()) check(details->grab().save(QDir(detailsReport).filePath("diagnostics.png")),"save the native diagnostic layout");
    detailTabs->setCurrentIndex(1);check(log->isVisible(),"the bounded log is available in one tab change");
    QCoreApplication::processEvents();
    for (const auto *name:{"openLogPushButton","copyLogPushButton","clearLogPushButton"})
        check(!window.findChild<QPushButton *>(name)->isDefault(),"opening logs does not turn a toolbar icon into the dialog's submit action");
    if (!detailsReport.isEmpty()) check(details->grab().save(QDir(detailsReport).filePath("details-logs.png")),"save the native log layout and toolbar");
    if(!detailsReport.isEmpty() && QGuiApplication::platformName()=="windows") {
        // Native macOS tray menus are NSMenu surfaces, outside QWidget::grab.
        const auto captureMenu=[&](QMenu *menu,const QString &name) {
            menu->popup(details->mapToGlobal(QPoint(24,80)));waitForUi([&]{return menu->isVisible();});
            menu->setActiveAction(menu->actions().first());QCoreApplication::processEvents();
            check(menu->grab().save(QDir(detailsReport).filePath(name)),"save compact neutral menu styling");menu->hide();
        };
        captureMenu(appMenu,"application-menu.png");
        captureMenu(window.findChild<QSystemTrayIcon *>()->contextMenu(),"tray-menu.png");
        captureMenu(window.findChild<QToolButton *>("profileMenuButton")->menu(),"profile-menu.png");
    }
    emit session->diagnostic("authentication_started");
    check(reportView->findItems("authentication_started", Qt::MatchExactly, 1).isEmpty(),
        "the hidden overview does not render incoming diagnostics");
    detailTabs->setCurrentIndex(0);
    check(reportView->findItems("authentication_started", Qt::MatchExactly, 1).size()==1,
        "opening the overview immediately renders the latest diagnostics");
    detailTabs->setCurrentIndex(1);
    check(!log->toPlainText().contains("QFont::setPointSize: Point size <= 0"),
        "drawing the home and menus does not pass an invalid point size to Qt");
    auto *copyLog = window.findChild<QPushButton *>("copyLogPushButton");
    auto *clearLog = window.findChild<QPushButton *>("clearLogPushButton");
    emit logger.entryAdded("Queued first\nQueued second");
    emit logger.entryAdded("Queued third");
    copyLog->click();
    check(QApplication::clipboard()->text()==log->toPlainText()
        && log->toPlainText().endsWith("Queued first\nQueued second\nQueued third"),
        "copy includes all pending log entries in arrival order");
    const QIcon copyIcon(":/resource/copy.svg");
    const QIcon checkIcon(":/resource/check.svg");
    const auto iconMatches = [](const QPushButton *button, const QIcon &icon) {
        return button->icon().pixmap(button->iconSize()).toImage() == icon.pixmap(button->iconSize()).toImage();
    };
    waitForUi([&]{return iconMatches(copyLog, checkIcon);});
    copyLog->click();
    check(iconMatches(copyLog, checkIcon), "repeated copying keeps the confirmation visible");
    waitForUi([&]{return iconMatches(copyLog, copyIcon);});
    emit logger.entryAdded("Cleared before flush");
    clearLog->click();
    for (int i=0;i<1003;++i) emit logger.entryAdded(QString::number(i));
    waitForUi([&]{return log->toPlainText().endsWith("\n1002");});
    check(log->blockCount()==1000 && log->toPlainText().startsWith("3\n"),
        "the live log discards cleared entries and keeps the latest 1000 lines across batches");
    details->reject();QCoreApplication::processEvents();
    check(window.isVisible() && !details->isVisible() && session->state()==state,"closing details preserves the accessible home and connection");
    for (int i=0;i<2;++i) {
        window.findChild<QPushButton *>("detailsButton")->click();QCoreApplication::processEvents();
        check(details->isVisible() && session->state()==state,"reopening details preserves the session");
        details->reject();QCoreApplication::processEvents();
    }
    ScrollPaints editorPaints("loginTab");
    window.findChild<QAction *>("settingAction")->trigger();
    auto *initial = window.findChild<SettingWindow *>();
    check(initial && initial->isVisible(), "the first connection can be edited directly");
    auto *address = initial->findChild<QLineEdit *>("serverAddressLineEdit");
    auto *method = initial->findChild<QComboBox *>("authTypeComboBox");
    check(address->text() == "vpn.fudan.edu.cn" && address->isReadOnly()
        && method->currentData() == "httpsOauth2"
        && !initial->findChild<QComboBox *>("profileKindComboBox"),
        "Fudan has a fixed server and Web sign-in, with no second connection selector");
    auto *editorScroll = initial->findChild<QScrollArea *>("loginTab");
    waitForUi([&] { return !editorPaints.offsets.isEmpty()
        && initial->findChild<QPushButton *>("saveProfileButton")->isEnabled(); });
    check(editorScroll->verticalScrollBar()->value() == 0
        && std::all_of(editorPaints.offsets.cbegin(), editorPaints.offsets.cend(), [](int value) { return value == 0; }),
        "the connection editor stays at the top from its first paint through credential loading");
    initial->reject();
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    check(session->state()==state, "opening and cancelling the editor does not start a session");
    auto *gear=window.findChild<QToolButton *>("preferencesButton");
    check(!gear->menu(),"the settings gear opens settings without an extra menu layer");
    ScrollPaints preferencesPaints("applicationSettingsScroll");
    gear->click();QCoreApplication::processEvents();
    auto *settings=window.findChild<QDialog *>("applicationSettingsDialog");
    check(settings && settings->isVisible() && !qobject_cast<SettingWindow *>(settings)
        && !settings->findChild<QLineEdit *>("serverAddressLineEdit"),"the gear opens application settings with a separate responsibility");
    auto *preferencesScroll = settings->findChild<QScrollArea *>("applicationSettingsScroll");
    waitForUi([&] { return !preferencesPaints.offsets.isEmpty()
        && preferencesScroll->verticalScrollBarPolicy() == Qt::ScrollBarAsNeeded; });
    if (preferencesPaints.barPainted)
        std::cerr << "Preferences viewport: " << preferencesScroll->viewport()->height()
                  << ", content: " << preferencesScroll->widget()->height()
                  << ", range: " << preferencesScroll->verticalScrollBar()->maximum() << '\n';
    check(!preferencesPaints.barPainted, "application settings paint without a temporary scrollbar");
    settings->resize(320, 360);
    waitForUi([&] { return preferencesScroll->verticalScrollBar()->isVisible(); });
    settings->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    window.findChild<QAction *>("settingAction")->trigger();
    auto *editor=window.findChild<SettingWindow *>();
    check(editor && editor->isVisible() && !editor->findChild<QComboBox *>("languageComboBox")
        && !window.findChild<QDialog *>("applicationSettingsDialog"),
        "the preset menu opens a separate connection editor without application preferences");
    editor->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
    if (!report.isEmpty()) check(window.grab().save(QDir(report).filePath("home.png")),"save actual Qt home screenshot");
    const auto original=window.size();window.resize(320,460);QCoreApplication::processEvents();
    auto *button=window.findChild<QPushButton *>("connectButton");
    auto *detailsButton=window.findChild<QPushButton *>("detailsButton");
    const QRect actionRect(button->mapTo(&window,QPoint()),button->size());
    const QRect detailsRect(detailsButton->mapTo(&window,QPoint()),detailsButton->size());
    check(window.width()==320 && window.rect().contains(actionRect) && button->height()>=44,"compact home keeps its main action in bounds at 320 logical pixels");
    check(window.rect().contains(detailsRect) && detailsRect.left()-actionRect.right()==9
        && actionRect.height()==detailsRect.height() && detailsRect.width()==detailsRect.height()
        && qAbs(actionRect.united(detailsRect).center().x()-window.rect().center().x())<=1,
        "the centered action pair uses a square, aligned details control at narrow widths");
    check(detailsButton->text().isEmpty() && !detailsButton->icon().isNull() && !detailsButton->toolTip().isEmpty()
        && !detailsButton->accessibleName().isEmpty(),"the diagnostics icon remains discoverable and accessible");
    auto *profile=window.findChild<QToolButton *>("profileMenuButton");
    check(profile->width()<=profile->sizeHint().width()+1,
        "the preset selector uses its natural width instead of stretching toward the settings gear");
    const auto profileName=profile->text();
    profile->setText("X");QCoreApplication::processEvents();const auto shortWidth=profile->width();
    profile->setText("A longer preset");QCoreApplication::processEvents();
    check(profile->width()>shortWidth,"the preset selector adapts its width to its caption");
    const auto longName=QString(64,QChar('W'));
    profile->setText(longName);QCoreApplication::processEvents();window.resize(320,460);QCoreApplication::processEvents();
    check(window.width()==320 && profile->text()==longName && profile->width()<=window.width(),
        "a long profile name must keep its full value without expanding the compact window");
    profile->setText(profileName);QCoreApplication::processEvents();
    PresentationHelpers::activateWindow(&window);profile->setFocus();
    waitForUi([&]{return QApplication::focusWidget()==profile;});
    for (int i=0;i<16 && QApplication::focusWidget()!=button;++i) {
        QKeyEvent tab(QEvent::KeyPress,Qt::Key_Tab,Qt::NoModifier);
        auto *focused=QApplication::focusWidget();check(focused,"home keeps an accessible keyboard focus");
        QApplication::sendEvent(focused,&tab);
    }
    check(QApplication::focusWidget()==button,"Tab navigation reaches the main connection action without opening details");
    if (!report.isEmpty()) check(window.grab().save(QDir(report).filePath("home-320.png")),"save narrow Qt screenshot");
    window.resize(original);
}

int main(int argc,char **argv) {
    QApplication app(argc,argv);
#ifdef Q_OS_UNIX
    if (app.arguments().contains("--external-signal")) {
        QProcess child;child.start(app.applicationFilePath(),{"--wait-for-signal"});
        check(child.waitForStarted(10000),"external signal child startup");
        QByteArray output;
        while (!output.contains("READY") && child.waitForReadyRead(10000)) output+=child.readAllStandardOutput();
        check(output.contains("READY"),"external signal child must be ready before termination");
        check(::kill(pid_t(child.processId()),SIGTERM)==0,"send an actual host termination signal");
        check(child.waitForFinished(10000) && child.exitStatus()==QProcess::NormalExit && child.exitCode()==0,
            "external SIGTERM must complete ordered shutdown without a crash");
        return 0;
    }
#endif
    QApplication::setApplicationName("JustConnect-window-test-"+QUuid::createUuid().toString(QUuid::Id128));
    QApplication::setApplicationDisplayName("JustConnect");
    QStandardPaths::setTestModeEnabled(true);
    const auto configRoot=QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QTemporaryDir folder;
    ApplicationLogger logger;ApplicationLogFile log(folder.filePath("app.log"));
    {
        SavedConnectionStore manager;
        QSettings settings(manager.connectionPath(""),QSettings::IniFormat);
        const bool native = app.arguments().contains("--native-home");
        if (app.arguments().contains("--chinese-startup")) check(manager.setApplicationPreferences("zh_CN",true),"prepare persisted Chinese preference");
        if (app.arguments().contains("--invalid-language")) {
            QSettings state(QDir(configRoot).filePath("state.ini"),QSettings::IniFormat);state.setValue("Global/Language","unsupported");state.sync();
        }
        QLocale::setDefault(QLocale(QLocale::Chinese,QLocale::China));
        QString menuProfile;
        if (native) {
            DefaultSettings::reset(settings);
            settings.setValue("JustConnect/ProfileKind", "Custom");
            settings.sync();
            menuProfile=manager.createConnection("menu-fixture");
            check(!menuProfile.isEmpty(),"create an isolated profile for menu switching");
        }
        if (app.arguments().size()==1) recoveryStatus(logger,log);
        // UI preference tests retain the real core without requesting host network privileges.
        MainWindow window(&logger,&log,nullptr,[](CoreEngine *,NetworkPolicySession *) -> NetworkAccess * { return nullptr; });
        check(window.isVisible(),"normal startup must show the main window");
        settings.sync();
        check(settings.value("JustConnect/ServerAddress")=="vpn.fudan.edu.cn"
            && settings.value("JustConnect/AuthType")=="httpsOauth2",
            "startup persists the ready-to-use Fudan connection");
        check(window.focusWidget()==window.centralWidget(),"startup leaves focus on the home surface");
        if (app.arguments().contains("--auth-language")) authenticationLanguageChangesPreserveData(window);
        if (app.arguments().contains("--profile-language")) profileSetupLanguageChangesPreserveData(window);
        if (app.arguments().contains("--chinese-startup")) {
            check(ApplicationLanguage::instance().current()=="zh_CN" && window.findChild<QPushButton *>("connectButton")->text()==QString::fromUtf8("连接"),"a new process restores the saved Chinese preference");
            changeLanguageFromSettings(window,"en");
        }
        if (app.arguments().contains("--invalid-language")) {
            check(ApplicationLanguage::instance().current()=="en" && manager.language()=="unsupported","invalid preferences fall back to English without overwriting evidence");
            window.findChild<QAction *>("preferencesAction")->trigger();
            auto *invalid=window.findChild<QDialog *>("applicationSettingsDialog");
            bool explained=false;for (auto *label:invalid->findChildren<QLabel *>()) explained|=label->text().contains("saved language is invalid");
            check(explained,"invalid language fallback is visible in settings");invalid->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        }
        if (native) {
            nativeHome(window, logger);
            languagePreferences(window);
            profileMenusKeepTheirActions(window,menuProfile);
        }
        check(window.findChild<QLabel *>("statusTitleLabel")->text()!="Connected","disconnected cannot claim campus readiness");
        window.showMinimized();QCoreApplication::processEvents();
        check(window.isVisible(),"minimization must not hide the only window");
        window.showMaximized();window.showMinimized();
        window.findChild<QAction *>("trayShowAction")->trigger();QCoreApplication::processEvents();
        check(window.isVisible() && !window.isMinimized() && window.isMaximized(),"tray restoration preserves the user's maximized state");
        window.showNormal();window.close();QCoreApplication::processEvents();
        const bool tray=QSystemTrayIcon::isSystemTrayAvailable();
        check(tray ? window.isHidden() : window.isVisible(),"default close must use an available tray or keep the window reachable");
        window.show();
        auto *inspectNetwork = window.findChild<QAction *>("inspectNetworkAction");
        check(inspectNetwork, "network inspection is reachable from the main menu");
        inspectNetwork->trigger();
        QPointer<NetworkPolicyWindow> inspection = window.findChild<NetworkPolicyWindow *>();
        check(inspection && inspection->isVisible(), "network inspection opens without an active connection");
        inspectNetwork->trigger();
        check(window.findChildren<NetworkPolicyWindow *>().size() == 1, "reopening network inspection reuses its window");
        inspection->close();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        check(!inspection, "closed network inspection releases its window");
        QTcpServer stalledGateway;
        auto *connection=window.findChild<ConnectionSession *>();
        const bool activePreferences=app.arguments().contains("--active-preferences");
        if (activePreferences) {
            check(stalledGateway.listen(QHostAddress::LocalHost),"isolated active preference gateway");
            ConnectionOptions profile;profile.endpoint.server="127.0.0.1";profile.endpoint.port=stalledGateway.serverPort();
            check(connection && connection->start(profile,{}),"start a cancellable real core operation before editing preferences");
            auto *core=connection->findChild<CoreEngine *>();
            check(core,"session owns its core event source");
            const auto observedAt=QDateTime::currentDateTimeUtc();
            emit core->observation("renewal","succeeded",observedAt);
            emit core->observation("traffic","unavailable",observedAt);
            const auto detail=window.findChild<QLabel *>("statusDetailLabel")->text();
            check(detail.contains("Last Session renewal: Succeeded") && detail.contains("Last Traffic keepalive (campus DNS): Unavailable")
                && detail.contains("authorized") && detail.contains(observedAt.toLocalTime().toString(Qt::ISODate))
                && window.findChild<QSystemTrayIcon *>()->toolTip().contains(detail),
                "window and tray distinguish observed renewal from unavailable traffic probing and show its time");
        }
        auto *preferencesAction=window.findChild<QAction *>("preferencesAction");
        check(preferencesAction,"application preferences must be discoverable without a preset configuration");
        const auto openPreferences=[&] {
            preferencesAction->trigger();
            auto *dialog=window.findChild<QDialog *>("applicationSettingsDialog");
            check(dialog && dialog->isVisible(),"application preferences open independently of preset settings");
            return dialog;
        };
        auto *preferences=openPreferences();
        if (activePreferences) {
            check(!preferences->findChild<QLineEdit *>("usernameLineEdit")
                && preferences->findChild<QComboBox *>("languageComboBox")->isEnabled(),"application settings remain independent and editable during a connection");
            window.findChild<QAction *>("settingAction")->trigger();
            auto *editor=window.findChild<SettingWindow *>();
            check(editor && editor!=preferences && !editor->findChild<QLineEdit *>("usernameLineEdit")->isEnabled()
                && editor->findChild<QLabel *>("profileReadOnlyHint")->isVisible(),
                "the separate active connection editor remains read-only");
            editor->reject();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        }
        if (app.arguments().contains("--preferences-failure")) {
            check(SavedConnectionStore().setCloseToTray(true),"prepare previous global preference");
            const auto state=QDir(configRoot).filePath("state.ini");
            QFile input(state);check(input.open(QIODevice::ReadOnly),"read original preference");const auto original=input.readAll();input.close();
            check(QFile::remove(state) && QDir().mkdir(state),"inject isolated preference storage failure");
            preferences->findChild<QComboBox *>("languageComboBox")->setCurrentIndex(1);
            preferences->findChild<QComboBox *>("closeBehaviorComboBox")->setCurrentIndex(1);
            check(ApplicationLanguage::instance().current()=="en" && preferences->isVisible()
                && preferences->findChild<QComboBox *>("closeBehaviorComboBox")->currentIndex()==0
                && preferences->findChild<QComboBox *>("languageComboBox")->currentIndex()==0
                && !preferences->findChild<QLabel *>("preferenceError")->isHidden(),
                "failed immediate preference saves restore both controls and show the error");
            check(QDir().rmdir(state),"remove isolated failure fixture");
            QFile restore(state);check(restore.open(QIODevice::WriteOnly) && restore.write(original)==original.size(),"restore original preference fixture");restore.close();
            check(SavedConnectionStore().closeToTray(),"failed save cannot replace the previous preference");
        } else {
            preferences->findChild<QComboBox *>("closeBehaviorComboBox")->setCurrentIndex(1);
            check(window.isVisible() && !SavedConnectionStore().closeToTray(),"general preferences persist immediately without closing or disconnecting");
            if (!app.arguments().contains("--close-exits")) check(SavedConnectionStore().setCloseToTray(true),"restore default preference for explicit exit tests");
        }
        preferences->reject();
        QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
        if (activePreferences) {
            const auto state=connection->state();
            const auto source=manager.connectionPath("");QFile profileFile(source);check(profileFile.open(QIODevice::ReadOnly),"read active public profile");
            const auto unchanged=profileFile.readAll();profileFile.close();
            changeLanguageFromSettings(window,"zh_CN");
            check(connection->isActive() && connection->state()==state && window.findChild<QPushButton *>("connectButton")->text()==QString::fromUtf8("取消"),"language changes preserve an active pending connection and its cancel action");
            changeLanguageFromSettings(window,"en");
            check(profileFile.open(QIODevice::ReadOnly) && profileFile.readAll()==unchanged,"global language changes do not rewrite the preset profile");profileFile.close();
            check(connection->isActive() && connection->state()==ConnectionState::Starting,"preference saves must not stop or restart the active session");
            connection->stop();
        }
        bool quitIntercepted=false;
        QElapsedTimer idleQuit;
        TerminationRequests termination;
        QObject::connect(&termination,&TerminationRequests::requested,&window,[&] {
            check(QThread::currentThread()==app.thread(),"termination request must reach the GUI thread");
            quitIntercepted=true;window.gracefullyQuit();
        });
        QTimer::singleShot(0,&app,[&] {
            if (app.arguments().contains("--close-exits")) {quitIntercepted=true;window.close();return;}
            if (app.arguments().contains("--wait-for-signal")) {
                QFile output;check(output.open(stdout,QIODevice::WriteOnly),"signal child output");
                output.write("READY\n");output.flush();return;
            }
            if (app.arguments().contains("--system-session")) {quitIntercepted=true;window.endSystemSession();return;}
            if (app.arguments().contains("--termination")) {std::raise(SIGTERM);return;}
#ifdef Q_OS_UNIX
            if (app.arguments().contains("--interrupt")) {std::raise(SIGINT);return;}
            if (app.arguments().contains("--hangup")) {std::raise(SIGHUP);return;}
#endif
            if (native) {
                check(!connection->isActive(), "idle menu quit must be measured without an active connection");
                idleQuit.start();
                auto *exitAction = window.findChild<QAction *>("exitAction");
                check(exitAction->menuRole() == QAction::QuitRole && exitAction->shortcut().matches(QKeySequence::Quit)
                    == QKeySequence::ExactMatch, "the native menu and Quit shortcut share the exit action");
                exitAction->trigger();
                quitIntercepted = true;
                return;
            }
            QEvent quit(QEvent::Quit);
            quitIntercepted = QCoreApplication::sendEvent(&app, &quit);
            check(!quit.isAccepted(), "the original platform quit request is deferred until ordered cleanup");
        });
        QTimer::singleShot(10000,&app,[&]{check(false,"ordered quit did not complete");});
        check(app.exec()==0 && quitIntercepted,"application quit must enter the shared asynchronous shutdown");
        if (native) check(idleQuit.isValid() && idleQuit.elapsed() < 1500,
            "idle menu exit reaches application shutdown promptly");
    }
    check(QDir(configRoot).removeRecursively(),"isolated window-test settings cleanup");
}
