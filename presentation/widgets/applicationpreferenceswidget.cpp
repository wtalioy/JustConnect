#include "applicationpreferenceswidget.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/coordinators/controllerselectioncoordinator.h"
#include "presentation/presentationhelpers.h"
#include "infrastructure/settings/profilemanager.h"
#include "infrastructure/autostart/autostart.h"
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSystemTrayIcon>

ApplicationPreferencesWidget::ApplicationPreferencesWidget(QWidget *parent) : QWidget(parent) {
    auto *layout=new QFormLayout(this);layout->setSpacing(12);layout->setContentsMargins(0,0,0,0);
    layout->setRowWrapPolicy(QFormLayout::WrapAllRows);
    layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    language=new QComboBox(this);language->setObjectName("languageComboBox");
    language->addItem("English","en");language->addItem(QString::fromUtf8("简体中文"),"zh_CN");
    language->setCurrentIndex(language->findData(ApplicationLanguage::instance().current()));
    languageLabel=new QLabel(this);languageLabel->setBuddy(language);layout->addRow(languageLabel,language);
    behavior=new QComboBox(this);behavior->setObjectName("closeBehaviorComboBox");
    behavior->addItem(QString(),true);behavior->addItem(QString(),false);
    behavior->setCurrentIndex(ProfileManager().closeToTray()?0:1);
    behaviorLabel=new QLabel(this);behaviorLabel->setBuddy(behavior);layout->addRow(behaviorLabel,behavior);
    autoStart=new QCheckBox(this);autoStart->setObjectName("autoStartCheckBox");
    autoStart->setChecked(ProfileManager().autoStartEnabled());layout->addRow(autoStart);
    silentStart=new QCheckBox(this);silentStart->setObjectName("silentStartCheckBox");
    silentStart->setChecked(ProfileManager().silentStartEnabled());layout->addRow(silentStart);
    hint=new QLabel(this);hint->setWordWrap(true);hint->setProperty("secondary",true);layout->addRow(hint);
    controller=new QPushButton(this);controller->setObjectName("controllerSettingsButton");layout->addRow(controller);
    auto *selection=new ControllerSelectionCoordinator(this,this);
    connect(controller,&QPushButton::clicked,selection,[this,selection] {
        controller->setEnabled(false);
        selection->choose([this](std::optional<QString>){controller->setEnabled(true);},true);
    });
    error=new QLabel(this);error->setObjectName("preferenceError");error->setWordWrap(true);error->setProperty("warning",true);error->hide();layout->addRow(error);
    connect(language,&QComboBox::currentIndexChanged,this,&ApplicationPreferencesWidget::savePreferences);
    connect(behavior,&QComboBox::currentIndexChanged,this,&ApplicationPreferencesWidget::savePreferences);
    connect(silentStart,&QCheckBox::toggled,this,[this](bool enabled) {
        if (ProfileManager().setSilentStartEnabled(enabled)) {error->hide();return;}
        QSignalBlocker blocker(silentStart);silentStart->setChecked(ProfileManager().silentStartEnabled());
        errorText=QT_TR_NOOP("Could not save background startup. Your previous setting is unchanged.");
        error->setText(tr(errorText));error->show();
    });
    connect(autoStart,&QCheckBox::toggled,this,[this](bool enabled) {
        const auto result=AutoStart::setEnabled(enabled);
        if (result.succeeded() && ProfileManager().setAutoStartEnabled(enabled)) {error->hide();return;}
        QSignalBlocker blocker(autoStart);autoStart->setChecked(ProfileManager().autoStartEnabled());
        errorText=result.succeeded() ? QT_TR_NOOP("Startup registration changed, but its preference could not be saved. Check it before retrying.") : nullptr;
        error->setText(errorText ? tr(errorText) : PresentationHelpers::platformOperationMessage(result));error->show();
    });
    retranslate();
}
void ApplicationPreferencesWidget::savePreferences() {
    if (ApplicationLanguage::instance().savePreferences(language->currentData().toString(),behavior->currentData().toBool())) {
        errorText=nullptr;error->hide();return;
    }
    const QSignalBlocker languageBlocker(language),behaviorBlocker(behavior);
    language->setCurrentIndex(language->findData(ApplicationLanguage::instance().current()));
    behavior->setCurrentIndex(ProfileManager().closeToTray()?0:1);
    errorText=QT_TR_NOOP("Could not save preferences. Your previous settings are unchanged.");
    error->setText(tr(errorText));error->show();
}
void ApplicationPreferencesWidget::retranslate() {
    languageLabel->setText(tr("Language"));behaviorLabel->setText(tr("When closing the window"));
    const QSignalBlocker blocker(behavior);
    behavior->setItemText(0,tr("Keep running in the system tray"));behavior->setItemText(1,tr("Disconnect and exit"));
    autoStart->setText(tr("Launch at sign-in"));silentStart->setText(tr("Start in the background"));
    QString explanation=tr("General settings save automatically.");
    if (!ProfileManager::supportsLanguage(ProfileManager().language()))
        explanation+='\n'+tr("The saved language is invalid. English is being used.");
    else if (!QSystemTrayIcon::isSystemTrayAvailable())
        explanation+='\n'+tr("No system tray is available. Use Exit in Details to quit.");
    hint->setText(explanation);
    controller->setText(tr("Clash coexistence…"));
    if (errorText) error->setText(tr(errorText));
}
void ApplicationPreferencesWidget::changeEvent(QEvent *event) {
    QWidget::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) retranslate();
}
