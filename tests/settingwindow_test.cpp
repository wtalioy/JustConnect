#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <cstdlib>
#include <QFileDialog>
#include <QLabel>
#include <QFormLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QKeyEvent>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QStandardPaths>
#include <QUuid>
#include <QScopeGuard>
#include <QSpinBox>
#include <QScrollArea>
#include <QScrollBar>
#include "presentation/widgets/applicationpreferenceswidget.h"
#include "tests/uiwait.h"
#include "presentation/i18n/applicationlanguage.h"
#include <QTemporaryDir>
#include <QTimer>
#include <QElapsedTimer>
#include <QComboBox>
#include <QSemaphore>
#include <atomic>
#include "application/savedconnectionservice.h"
#include "presentation/appearance/applicationappearance.h"
#include "infrastructure/autostart/autostart.h"
#include "presentation/presentationhelpers.h"
#include "tests/credentialstorefixture.h"
#include <iostream>
#include "presentation/dialogs/settingwindow/settingwindow.h"
#include "infrastructure/settings/savedconnectionstore.h"
#include "infrastructure/storage/applicationpaths.h"
#include "application/defaultsettings.h"
static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
static int checkFormRows(QWidget *view) {
    int checked=0;
    for(auto *form:view->findChildren<QFormLayout *>()) {
        for(int row=0;row<form->rowCount();++row) {
            auto *labelItem=form->itemAt(row,QFormLayout::LabelRole),*fieldItem=form->itemAt(row,QFormLayout::FieldRole);
            auto *label=labelItem?labelItem->widget():nullptr,*field=fieldItem?fieldItem->widget():nullptr;
            if (fieldItem && fieldItem->layout() && fieldItem->layout()->count()==1)
                field=fieldItem->layout()->itemAt(0)->widget();
            if(!label || !field || !label->isVisible() || !field->isVisible() || label->geometry().right()>=field->x()) continue;
            const auto offset=label->geometry().center().y()-field->geometry().center().y();
            if (std::abs(offset)>1) std::cerr<<label->objectName().toStdString()<<" offset: "<<offset<<'\n';
            check(std::abs(offset)<=1,
                "visible form labels are vertically centered beside their fields");
            ++checked;
        }
    }
    return checked;
}
static void write(const QString &path,const QByteArray &data) { check(QDir().mkpath(QFileInfo(path).absolutePath()),"create fixture directory"); QFile f(path); check(f.open(QIODevice::WriteOnly) && f.write(data)==data.size(),"write fixture"); }
static QByteArray read(const QString &path) { QFile f(path); check(f.open(QIODevice::ReadOnly),"read fixture"); return f.readAll(); }
template<class P> static void until(P done) {
    QElapsedTimer timer;timer.start();
    while (!done() && timer.elapsed()<6000) QApplication::processEvents(QEventLoop::AllEvents,10);
    check(done(),"bounded settings operation");
}
int main(int argc,char **argv) {
    QTemporaryDir directory; check(directory.isValid(),"isolated settings");
    QStandardPaths::setTestModeEnabled(true);
    QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
    QApplication app(argc,argv);
    ApplicationAppearance::install();
    app.setApplicationName("JustConnect settings test-"+QUuid::createUuid().toString(QUuid::Id128));
    app.setOrganizationName("JustConnect-test");
    const auto configRoot=QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    const auto dataRoot=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    const auto cleanup=qScopeGuard([&] { QDir(configRoot).removeRecursively(); QDir(dataRoot).removeRecursively(); });
    QSettings settings(directory.filePath("profile.ini"),QSettings::IniFormat); DefaultSettings::reset(settings);
    settings.setValue("Credential/Username","fixture-user");
    settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("fixture-password").toBase64()));
    settings.setValue("JustConnect/ServerAddress","vpn.example.invalid");
    settings.setValue("JustConnect/AuthID","persisted-id"); settings.setValue("JustConnect/AuthSubType","password");
    settings.setValue(DefaultSettings::SignInMethodName,"Campus password");
    settings.setValue("Credential/OtherAccount/Ticket","retained-ticket");
    settings.setValue("OtherApplication/Value","retained-value"); settings.sync();
    settings.setValue("JustConnect/SOCKS5Port",0);settings.setValue("JustConnect/HTTPPort",19443);
    settings.setValue("JustConnect/DNSTTL",61);settings.setValue("JustConnect/KeepAliveMode","target");
    settings.setValue("JustConnect/KeepAliveURL","https://campus.example.invalid/status");settings.sync();
    auto backend=std::make_unique<MemoryCredentialStore>();auto *store=backend.get();CredentialAccess access(std::move(backend));
    auto ready=[&] {until([&]{return !access.isBusy(settings.fileName());});app.processEvents();};
    QTimer unexpectedMessage;
    QObject::connect(&unexpectedMessage,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) if(auto *box=qobject_cast<QMessageBox *>(widget);box && box->isVisible()) {
            std::cerr<<"Unexpected initial settings message: "<<box->text().toStdString()<<'\n';std::exit(1);
        }
    });unexpectedMessage.start(10);
    // Saving an unrelated change must preserve the selected opaque identity.
    { auto *initial=new SettingWindow(nullptr,&access,CredentialAccess::source(settings,ApplicationPaths::clientDataFile("fixture"))); initial->show();ready();
      initial->resize(640,480); app.processEvents();
      check(checkFormRows(initial)>=3,"check real connection, sign-in and account rows");
      check(initial->height()<=480,"settings fit a short screen without forcing the dialog beyond its bounds");
      check(!initial->findChild<QComboBox *>("languageComboBox") && initial->findChild<QLineEdit *>("serverAddressLineEdit"),
          "connection settings contain connection fields without global preferences");
      initial->findChild<QCheckBox *>("tlsVerifyCheckBox")->setChecked(false);
      initial->findChild<QCheckBox *>("allowUnverifiedNodesCheckBox")->setChecked(true);
      app.processEvents();
      auto *scroll=initial->findChild<QScrollArea *>("loginTab");
      check(scroll && scroll->verticalScrollBar()->maximum()>0 && initial->height()<=480,"long settings and TLS warnings scroll within the dialog");
      auto *username=initial->findChild<QLineEdit *>("usernameLineEdit"); username->setFocus();
      QKeyEvent tab(QEvent::KeyPress,Qt::Key_Tab,Qt::NoModifier); QApplication::sendEvent(username,&tab);app.processEvents();
      auto *password=initial->findChild<QLineEdit *>("passwordLineEdit");
      check(QApplication::focusWidget()==password && scroll->viewport()->rect().contains(password->mapTo(scroll->viewport(),QPoint(0,0))),"keyboard focus brings lower settings into view");
      auto *footer=initial->findChild<QDialogButtonBox *>("buttonBox");
      check(footer->buttons().size()==2,"connection settings have exactly one save action and one cancel action");
      check(initial->rect().contains(footer->geometry()),"apply and cancel remain visible outside the scrolling settings");
      for (const auto *name:{"importPushButton","exportPushButton","resetDefaultPushButton"}) {
          auto *action=initial->findChild<QPushButton *>(name);
          check(action && action->isVisible() && !action->text().isEmpty() && !action->icon().isNull()
              && !action->isFlat() && !scroll->isAncestorOf(action)
              && initial->rect().contains(QRect(action->mapTo(initial,QPoint()),action->size())),
              "labeled profile actions stay visible in the fixed footer");
      }
      auto *method=initial->findChild<QComboBox *>("authTypeComboBox");
      check(method->currentText()=="Campus password" && method->itemText(method->count()-1)=="Find sign-in methods…"
          && initial->findChild<QPushButton *>("cancelAuthQueryButton")->isHidden(),
          "the saved sign-in name and discovery share one dropdown in the idle editor");
      check(initial->findChild<QGroupBox *>("serverGroup")->font().pointSizeF()>method->font().pointSizeF(),
          "section headings have a larger type size than form controls");
      auto *remember=initial->findChild<QCheckBox *>("rememberAuthenticationCheckBox");
      check(remember && remember->isChecked(),"remember authentication is checked by default");
      initial->findChild<QCheckBox *>("tlsVerifyCheckBox")->setChecked(false);
      check(!initial->findChild<QSpinBox *>("socks5PortSpinBox") && !initial->findChild<QComboBox *>("keepAliveModeComboBox"),
          "technical proxy and traffic-probe controls are absent from everyday settings");
      initial->setConnectAfterSave(true);int intents=0;
      QObject::connect(initial,&SettingWindow::connectRequested,[&]{++intents;});
      initial->findChild<QPushButton *>("saveProfileButton")->click(); ready();
      check(intents==1,"implicit setup resumes the requested connection once after a successful save");
      check(settings.value("JustConnect/AuthID")=="persisted-id" && settings.value("JustConnect/AuthSubType")=="password"
          && settings.value(DefaultSettings::SignInMethodName)=="Campus password",
          "the selected authentication identity and displayed name survive settings reload/apply");
      const auto reloaded=SavedConnectionService::load(settings);
      check(!reloaded.tls.verify && reloaded.proxy.socksBind.isEmpty()
          && reloaded.proxy.httpBind=="127.0.0.1:19443" && reloaded.dns.ttl==61 && reloaded.behavior.rememberAuthentication
          && reloaded.keepAlive.mode=="target" && reloaded.keepAlive.url=="https://campus.example.invalid/status",
          "validated settings draft and reloaded connection share TLS, disabled listener, port and DNS values"); }
    unexpectedMessage.stop();
    const auto cache=ApplicationPaths::clientDataFile("fixture"),otherCache=ApplicationPaths::clientDataFile("other");
    check(!QFileInfo::exists(cache) && !QFileInfo::exists(otherCache),"locating legacy cache creates no plaintext files");
    write(cache,"current authentication"); write(otherCache,"other authentication");
    QString expectedText,fileSelection; bool shown=false;
    int messageResult=QMessageBox::Ok;
    QTimer dismiss;
    QObject::connect(&dismiss,&QTimer::timeout,[&] {
        for (auto *widget:QApplication::topLevelWidgets()) {
            if (auto *message=qobject_cast<QMessageBox *>(widget)) {
                check(!expectedText.isEmpty() && message->text()==expectedText,"only the expected operation message is shown");
                shown=true; auto *choice=message->button(QMessageBox::StandardButton(messageResult));
                check(choice!=nullptr,"expected dialog choice exists"); choice->click();
            } else if (auto *dialog=qobject_cast<QFileDialog *>(widget); dialog && dialog->isVisible() && !fileSelection.isEmpty()) {
                const auto path=fileSelection; fileSelection.clear();
                dialog->setDirectory(QFileInfo(path).absolutePath()); dialog->selectFile(QFileInfo(path).fileName());
                check(QMetaObject::invokeMethod(dialog,"accept"),"accept selected test file");
            }
        }
    }); dismiss.start(1);
    auto open=[&] { auto *window=new SettingWindow(nullptr,&access,CredentialAccess::source(settings,ApplicationPaths::clientDataFile("fixture"))); window->show();ready(); return window; };
    settings.setValue("JustConnect/KeepAliveURL","ssh://campus.example.invalid:22");settings.sync();
    QPointer<SettingWindow> window=open();
    expectedText=QCoreApplication::translate("SettingWindow","Check the server, sign-in method, ports, DNS and probe target. Nothing was saved.");shown=false;
    window->findChild<QPushButton *>("saveProfileButton")->click();ready();
    check(shown && window && settings.value("JustConnect/KeepAliveURL")=="ssh://campus.example.invalid:22",
        "hidden advanced settings still pass core validation before any save");
    window->reject();ready();settings.setValue("JustConnect/KeepAliveURL","https://campus.example.invalid/status");
    settings.setValue("JustConnect/KeepAliveMode","off");settings.sync();
    window=open();expectedText.clear();window->findChild<QPushButton *>("saveProfileButton")->click();ready();
    check(settings.value("JustConnect/KeepAliveMode")=="off" && settings.value("JustConnect/KeepAliveURL")=="https://campus.example.invalid/status",
        "simplifying the editor preserves a disabled traffic mode and its saved target");
    window=open();
    ApplicationPreferencesWidget preferences(nullptr);
    // Use the content's preferred width to exercise side-by-side rows; narrow wrapping has separate coverage.
    preferences.resize(preferences.sizeHint().expandedTo(QSize(540,560)));preferences.show();app.processEvents();
    check(checkFormRows(&preferences)==2,"check both global preference dropdown rows");preferences.hide();
    const auto statePath=QDir(QFileInfo(SavedConnectionStore().connectionPath("")).absolutePath()).filePath("state.ini");
    const auto retainedTTL=settings.value("JustConnect/DNSTTL");
    check(SavedConnectionStore().setSilentStartEnabled(false),"seed an existing global preference before injecting its write failure");
    check(QFile::rename(statePath,statePath+".backup") && QDir().mkdir(statePath),"simulate global preference write failure");
    preferences.findChild<QCheckBox *>("silentStartCheckBox")->setChecked(true);
    check(window && window->isVisible() && settings.value("JustConnect/DNSTTL")==retainedTTL
        && !preferences.findChild<QCheckBox *>("silentStartCheckBox")->isChecked()
        && !preferences.findChild<QLabel *>("preferenceError")->isHidden(),
        "global preference failure restores its control and leaves the profile unchanged");
    check(QDir().rmdir(statePath) && QFile::rename(statePath+".backup",statePath),"repair global preference storage");
    check(!SavedConnectionStore().silentStartEnabled(),"failed preference write preserves the previous choice");
    expectedText.clear();window->reject();ready();
    settings.setValue("JustConnect/SecondaryDNS","not-an-address");settings.sync();window=open();
    expectedText=QCoreApplication::translate("SettingWindow","Check the server, sign-in method, ports, DNS and probe target. Nothing was saved."); window->findChild<QPushButton *>("saveProfileButton")->click();
    check(shown && window->isVisible() && settings.value("JustConnect/SecondaryDNS")=="not-an-address" && !QFileInfo::exists(cache) && store->values.value(ConnectionCredentialVault::legacyCacheKey(settings.value(ConnectionCredentialVault::ScopeSetting).toString()))=="current authentication","core validation rejects bad DNS before persistence or cache changes");
    window->reject();ready();settings.setValue("JustConnect/SecondaryDNS","");settings.sync();window=open();
    window->findChild<QLineEdit *>("serverAddressLineEdit")->setText("changed.example.invalid");
    auto *method=window->findChild<QComboBox *>("authTypeComboBox");method->setCurrentIndex(method->findData("psw"));
    const auto startup=AutoStart::setEnabled(true);
    check(!startup.succeeded() && !startup.mayHaveChanged,"invalid test startup identity is rejected before mutation");
    auto *autoStart = preferences.findChild<QCheckBox *>("autoStartCheckBox");
    autoStart->setChecked(true);
    check(preferences.isSavingStartup() && !autoStart->isEnabled(),
        "autostart keeps its control busy while the system command runs outside the UI");
    UiWait::until(__FILE__, __LINE__, [&] { return !preferences.isSavingStartup(); });
    check(window->isVisible() && !SavedConnectionStore().autoStartEnabled()
        && autoStart->isEnabled() && !autoStart->isChecked()
        && preferences.findChild<QLabel *>("preferenceError")->text()==PresentationHelpers::platformOperationMessage(startup),
        "autostart failure is inline, restores the choice, and keeps the connection draft");
    const auto startupMessage=preferences.findChild<QLabel *>("preferenceError")->text();
    check(!startup.detail.isEmpty() && !startupMessage.contains(startup.detail),"raw platform diagnostics do not mix with localized user hints");
    check(ApplicationLanguage::instance().savePreferences("zh_CN",SavedConnectionStore().closeToTray()),"switch language while an operation error is visible");
    app.processEvents();
    check(preferences.findChild<QLabel *>("preferenceError")->text()==PresentationHelpers::platformOperationMessage(startup)
        && preferences.findChild<QLabel *>("preferenceError")->text()!=startupMessage,"visible operation errors retranslate from their stored typed result");
    check(ApplicationLanguage::instance().savePreferences("en",SavedConnectionStore().closeToTray()),"restore English after the inline error language check");
    app.processEvents();
    check(settings.value("JustConnect/ServerAddress")=="vpn.example.invalid" && !QFileInfo::exists(cache)
        && store->values.value(ConnectionCredentialVault::legacyCacheKey(settings.value(ConnectionCredentialVault::ScopeSetting).toString()))=="current authentication",
        "failed startup operation does not mutate profile settings or authentication");
    expectedText.clear();
    window->findChild<QPushButton *>("saveProfileButton")->click(); ready();
    check(settings.value("JustConnect/ServerAddress")=="changed.example.invalid" && !QFileInfo::exists(cache) && read(otherCache)=="other authentication","legacy cache is sealed and other profiles remain unchanged after saving");
    write(cache,"preserved authentication"); settings.setValue("JustConnect/ExtraArguments","obsolete-argument");
    window=open(); window->findChild<QPlainTextEdit *>("domainDnsRulesEdit")->setPlainText("service.example.invalid");
    window->findChild<QPushButton *>("saveProfileButton")->click(); ready();
    check(!settings.contains("JustConnect/ExtraArguments") && settings.value("JustConnect/DNSTTL")==61 && settings.value(DefaultSettings::DomainDnsRules)=="service.example.invalid" && read(cache)=="preserved authentication","obsolete-field cleanup, network edits and refreshed URL previews retain valid authentication");
    window=open();window->setConnectAfterSave(true);int cancelledIntents=0;QObject::connect(window,&SettingWindow::connectRequested,[&]{++cancelledIntents;}); expectedText=QCoreApplication::translate("SettingWindow","Reset this draft to its defaults? Changes take effect after saving."); messageResult=QMessageBox::Yes;
    window->findChild<QPushButton *>("resetDefaultPushButton")->click(); expectedText.clear(); messageResult=QMessageBox::Ok;
    check(window->findChild<QLineEdit *>("serverAddressLineEdit")->text().isEmpty()
        && window->findChild<QCheckBox *>("rememberAuthenticationCheckBox")->isChecked(),"reset restores default connection values in the draft");
    window->findChild<QPushButton *>("dismissSettingsButton")->click(); ready();
    check(cancelledIntents==0 && settings.value("JustConnect/ServerAddress")=="changed.example.invalid" && read(cache)=="preserved authentication"
        && SavedConnectionService::load(settings).behavior.rememberAuthentication,"cancelled reset preserves configuration, cache consent and pending legacy archive");
    const auto imported=directory.filePath("import.ini");
    { QSettings source(imported,QSettings::IniFormat); DefaultSettings::reset(source); source.setValue("Credential/Username","imported-user"); source.setValue("JustConnect/ServerAddress","imported.example.invalid");
      source.remove("JustConnect/KeepAliveMode");source.setValue("JustConnect/KeepAlive",false);source.setValue("JustConnect/KeepAliveURL","https://imported.example.invalid/status");source.sync(); }
    const auto originalImport=read(imported);
    window=open(); fileSelection=imported; window->findChild<QPushButton *>("importPushButton")->click();
    check(fileSelection.isEmpty() && window->findChild<QLineEdit *>("usernameLineEdit")->text()=="imported-user","file import populates the window draft");
    window->findChild<QPushButton *>("dismissSettingsButton")->click(); ready();
    check(settings.value("Credential/Username")=="fixture-user" && read(imported)==originalImport && read(cache)=="preserved authentication","cancelled import changes neither source file nor saved profile/cache");
    window=open(); const auto exported=directory.filePath("export.ini"); fileSelection=exported;
    window->findChild<QPushButton *>("exportPushButton")->click();
    QSettings publicExport(exported,QSettings::IniFormat);
    check(fileSelection.isEmpty() && publicExport.value("JustConnect/ServerAddress")==settings.value("JustConnect/ServerAddress")
        && publicExport.value("Credential/Username")=="fixture-user" && !publicExport.contains("Credential/Password")
        && !publicExport.contains("Credential/TOTPSecret") && !publicExport.contains("Credential/OtherAccount/Ticket")
        && !publicExport.contains("OtherApplication/Value") && !publicExport.contains("JustConnect/LoginURL"),"export saves public configuration without credentials, private unknown fields or session URLs");
    window->reject(); app.processEvents();
    check(settings.value("Credential/OtherAccount/Ticket")=="retained-ticket" && settings.value("OtherApplication/Value")=="retained-value" && read(otherCache)=="other authentication","other accounts and application data survive all operations");
    // A blank field preserves the saved half of the credential pair; deletion is explicit.
    settings.setValue("JustConnect/AuthType","psw");settings.sync();
    const auto source=CredentialAccess::source(settings,cache);auto secured=source.connectionOptions;
    secured.credentials.password="saved-password";secured.credentials.totpSecret="saved-totp";
    ConnectionCredentialVault vault(*store);check(vault.save(source.scope,secured).succeeded(),"fixture secure account");
    auto other=secured;other.credentials.username="other-user";check(vault.save(source.scope,other).succeeded(),"fixture other secure account");
    // The deliberately conflicting old cache is retained, without preventing a public-only edit.
    window=open();window->findChild<QLineEdit *>("passwordLineEdit")->clear();
    window->findChild<QPlainTextEdit *>("domainDnsRulesEdit")->setPlainText("other.example.invalid");
    window->findChild<QPushButton *>("saveProfileButton")->click();ready();
    ConnectionCredentials loaded;
    check(vault.load(source.scope,secured,loaded).succeeded() && loaded.password=="saved-password"
        && loaded.totpSecret=="saved-totp" && settings.value(DefaultSettings::DomainDnsRules)=="other.example.invalid" && settings.value("JustConnect/DNSTTL")==61,"blank secret fields do not erase secure credentials when an unrelated public field changes");
    QFile::remove(cache);
    window=open();check(window->findChild<QLineEdit *>("passwordLineEdit")->text()=="saved-password","secure credentials populate the real settings window");
    window->findChild<QLineEdit *>("passwordLineEdit")->clear();window->findChild<QLineEdit *>("totpSecretLineEdit")->setText("replacement-totp");
    window->findChild<QPushButton *>("saveProfileButton")->click();ready();
    check(vault.load(source.scope,secured,loaded).succeeded() && loaded.password=="saved-password" && loaded.totpSecret=="replacement-totp","editing TOTP while leaving password blank preserves the password");
    window=open();
    expectedText=QCoreApplication::translate("SettingWindow","Clear saved passwords and authenticator keys for %1? Other accounts are unaffected.").arg("fixture-user");messageResult=QMessageBox::Yes;
    window->findChild<QPushButton *>("clearCredentialButton")->click();ready();expectedText.clear();messageResult=QMessageBox::Ok;
    check(vault.load(source.scope,secured,loaded).status==CredentialStatus::NotFound
        && vault.load(source.scope,other,loaded).succeeded() && loaded.password=="saved-password"
        && !settings.contains("Credential/Password") && window->findChild<QLineEdit *>("passwordLineEdit")->text().isEmpty()
        && window->findChild<QLabel *>("credentialStatusLabel")->isVisibleTo(window),"explicit settings deletion clears only the saved account and its displayed secrets, with visible confirmation");
    window->reject();ready();
    // Only the source value survives; neither window borrows the originating QSettings.
    const auto seed=[&](const QString &name,const QString &password) {
        QSettings origin(directory.filePath("late-"+name+".ini"),QSettings::IniFormat);
        DefaultSettings::reset(origin);origin.setValue("JustConnect/ServerAddress","vpn.example.invalid");
        origin.setValue("Credential/Username",name);
        const auto snapshot=CredentialAccess::source(origin,{});
        auto secured=snapshot.connectionOptions;secured.credentials.password=password;secured.credentials.totpSecret="saved-totp";
        check(vault.save(snapshot.scope,secured).succeeded(),"seed isolated late-result account");
        return snapshot;
    };
    const auto alice=seed("alice","alice-secret"),bob=seed("bob","bob-secret");
    QSemaphore entered,resume;std::atomic_bool gated=false;
    store->beforeRead=[&] {
        if (!gated.exchange(true)) {entered.release();check(resume.tryAcquire(1,6000),"release delayed settings read");}
    };
    QPointer<SettingWindow> old=new SettingWindow(nullptr,&access,alice);old->show();
    check(entered.tryAcquire(1,1000),"old settings credential read started");old->reject();delete old.data();
    QPointer<SettingWindow> current=new SettingWindow(nullptr,&access,bob);current->show();
    auto *password=current->findChild<QLineEdit *>("passwordLineEdit");
    password->setText("manual-draft");
    auto *save=current->findChild<QPushButton *>("saveProfileButton");
    check(save->isEnabled() && save->isDefault(),"Save is available while the credential read is queued");
    bool accepted=false;
    QObject::connect(current.data(),&QDialog::accepted,[&]{accepted=true;});
    save->click();
    check(!save->isEnabled() && !password->isEnabled(),"a queued save freezes the submitted draft");
    resume.release();
    until([&]{return accepted && !access.isBusy(alice.path) && !access.isBusy(bob.path);});
    store->beforeRead={};
    check(vault.load(alice.scope,alice.connectionOptions,loaded).succeeded() && loaded.password=="alice-secret"
        && vault.load(bob.scope,bob.connectionOptions,loaded).succeeded() && loaded.password=="manual-draft"
        && loaded.totpSecret=="saved-totp",
        "a queued save applies the password edit to the correct account and preserves its unread TOTP");
    // Retain the SMS/SSO contracts of the removed wizard in the shared editor.
    for (const auto &method:QStringList{"smsCheckCode","cas","httpsOauth2"}) {
        QSettings account(directory.filePath(method+".ini"),QSettings::IniFormat);DefaultSettings::reset(account);
        account.setValue("JustConnect/ServerAddress","vpn.example.invalid");account.setValue("JustConnect/AuthType",method);
        account.setValue("JustConnect/AuthID","selected-method");account.setValue("JustConnect/LoginDomain","campus");
        account.setValue("JustConnect/PhoneCountryCode","86");account.setValue("JustConnect/PhoneNumber","123456");account.sync();
        auto *editor=new SettingWindow(nullptr,&access,CredentialAccess::source(account,{}));editor->show();
        until([&]{return !access.isBusy(account.fileName());});app.processEvents();
        auto *country=editor->findChild<QLineEdit *>("countryCodeLineEdit");auto *phone=editor->findChild<QLineEdit *>("phoneNumberLineEdit");
        check(!editor->findChild<QLineEdit *>("passwordLineEdit")->isVisibleTo(editor)
            && phone->isVisibleTo(editor)==(method=="smsCheckCode"),"the editor exposes only the selected method's credential fields");
        if (method=="smsCheckCode") {country->setText("852");phone->setText("98765432");}
        editor->findChild<QPushButton *>("saveProfileButton")->click();until([&]{return !access.isBusy(account.fileName());});app.processEvents();
        check(account.value("JustConnect/AuthType")==method && account.value("JustConnect/AuthID")=="selected-method"
            && SavedConnectionService::load(account).endpoint.phone==(method=="smsCheckCode" ? "852-98765432" : "86-123456"),
            "SMS editing and credential-free SSO saves retain their method identity and hidden phone values");
        QApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    }
    std::cout<<"PASS: real settings validation, failures, verified legacy quarantine, import/reset cancellation and export\n";
}
