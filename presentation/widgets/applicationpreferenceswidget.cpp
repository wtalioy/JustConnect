#include "applicationpreferenceswidget.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/coordinators/controllerselectioncoordinator.h"
#include "presentation/presentationhelpers.h"
#include "infrastructure/settings/savedconnectionstore.h"
#include "infrastructure/autostart/autostart.h"
#include "presentation/widgets/alignedcheckbox.h"
#include <QComboBox>
#include <QEvent>
#include <QDebug>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSystemTrayIcon>
#include <QVBoxLayout>
#include <QtConcurrentRun>

ApplicationPreferencesWidget::ApplicationPreferencesWidget(QWidget *parent) : QWidget(parent) {
    const SavedConnectionStore preferences;
    auto *layout=new QVBoxLayout(this);layout->setSpacing(12);layout->setContentsMargins(0,0,0,0);
    behaviorGroup=new QGroupBox(this);layout->addWidget(behaviorGroup);
    auto *form=new QFormLayout(behaviorGroup);form->setHorizontalSpacing(12);form->setVerticalSpacing(8);form->setContentsMargins(0,0,0,0);
    form->setFormAlignment(Qt::AlignLeft|Qt::AlignTop);
    form->setLabelAlignment(Qt::AlignLeft|Qt::AlignVCenter);
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setFieldGrowthPolicy(QFormLayout::FieldsStayAtSizeHint);
    language=new QComboBox(this);language->setObjectName("languageComboBox");
    language->addItem("English","en");language->addItem(QString::fromUtf8("简体中文"),"zh_CN");
    language->setCurrentIndex(language->findData(ApplicationLanguage::instance().current()));
    languageLabel=new QLabel(this);languageLabel->setBuddy(language);form->addRow(languageLabel,language);
    behavior=new QComboBox(this);behavior->setObjectName("closeBehaviorComboBox");
    behavior->addItem(QString(),true);behavior->addItem(QString(),false);
    behavior->setCurrentIndex(preferences.closeToTray()?0:1);
    behaviorLabel=new QLabel(this);behaviorLabel->setBuddy(behavior);form->addRow(behaviorLabel,behavior);
    for (auto *choice:{language,behavior}) choice->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    for(auto *label:{languageLabel,behaviorLabel}) label->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Expanding);
    startupGroup=new QGroupBox(this);layout->addWidget(startupGroup);
    auto *startup=new QVBoxLayout(startupGroup);startup->setContentsMargins(0,0,0,0);startup->setSpacing(4);
    autoStart=new AlignedCheckBox(this);autoStart->setObjectName("autoStartCheckBox");
    autoStart->setChecked(preferences.autoStartEnabled());startup->addWidget(autoStart);
    silentStart=new AlignedCheckBox(this);silentStart->setObjectName("silentStartCheckBox");
    silentStart->setChecked(preferences.silentStartEnabled());startup->addWidget(silentStart);
    clashGroup=new QGroupBox(this);layout->addWidget(clashGroup);
    auto *clash=new QVBoxLayout(clashGroup);clash->setContentsMargins(0,0,0,0);clash->setSpacing(8);
    controller=new QPushButton(this);controller->setObjectName("controllerSettingsButton");controller->setAutoDefault(false);clash->addWidget(controller,0,Qt::AlignLeft);
    PresentationHelpers::setButtonIcon(controller,":/resource/controller.svg");
    hint=new QLabel(this);hint->setWordWrap(true);hint->setProperty("secondary",true);layout->addWidget(hint);
    auto *selection=new ControllerSelectionCoordinator(this,this);
    connect(controller,&QPushButton::clicked,selection,[this,selection] {
        controller->setEnabled(false);
        selection->choose([this](std::optional<QString>){controller->setEnabled(true);},true);
    });
    error=new QLabel(this);error->setObjectName("preferenceError");error->setWordWrap(true);error->setProperty("warning",true);error->hide();layout->addWidget(error);
    layout->addStretch();
    connect(language,&QComboBox::currentIndexChanged,this,&ApplicationPreferencesWidget::savePreferences);
    connect(behavior,&QComboBox::currentIndexChanged,this,&ApplicationPreferencesWidget::savePreferences);
    connect(silentStart,&QCheckBox::toggled,this,[this](bool enabled) {
        if (SavedConnectionStore().setSilentStartEnabled(enabled)) {error->hide();return;}
        QSignalBlocker blocker(silentStart);silentStart->setChecked(SavedConnectionStore().silentStartEnabled());
        errorText=QT_TR_NOOP("Could not save background startup. Your previous setting is unchanged.");
        error->setText(tr(errorText));error->show();
    });
    connect(autoStart, &QCheckBox::toggled, this, [this](bool enabled) {
        if (isSavingStartup()) return;
        error->hide();
        pendingAutoStart = enabled;
        autoStart->setEnabled(false);
        emit startupSaveStarted();
        startupOperation.setFuture(QtConcurrent::run([enabled] { return AutoStart::setEnabled(enabled); }));
    });
    connect(&startupOperation, &QFutureWatcher<PlatformOperationResult>::finished, this, [this] {
        const auto result = startupOperation.result();
        SavedConnectionStore preferences;
        if (!result.succeeded() || !preferences.setAutoStartEnabled(*pendingAutoStart)) {
            const QSignalBlocker blocker(autoStart);
            autoStart->setChecked(preferences.autoStartEnabled());
            operationError = result;
            if (!result.detail.isEmpty()) qWarning().noquote() << "Startup preference:" << result.detail;
            errorText = result.succeeded()
                ? QT_TR_NOOP("Startup registration changed, but its preference could not be saved. Check it before retrying.")
                : nullptr;
            error->setText(errorText ? tr(errorText) : PresentationHelpers::platformOperationMessage(result));
            error->show();
        }
        pendingAutoStart.reset();
        autoStart->setEnabled(true);
        emit startupSaveFinished();
    });
    retranslate();
}
void ApplicationPreferencesWidget::savePreferences() {
    if (ApplicationLanguage::instance().savePreferences(language->currentData().toString(),behavior->currentData().toBool())) {
        errorText=nullptr;error->hide();return;
    }
    const QSignalBlocker languageBlocker(language),behaviorBlocker(behavior);
    language->setCurrentIndex(language->findData(ApplicationLanguage::instance().current()));
    behavior->setCurrentIndex(SavedConnectionStore().closeToTray()?0:1);
    errorText=QT_TR_NOOP("Could not save preferences. Your previous settings are unchanged.");
    error->setText(tr(errorText));error->show();
}
void ApplicationPreferencesWidget::retranslate() {
    behaviorGroup->setTitle(tr("Behavior"));startupGroup->setTitle(tr("Startup"));clashGroup->setTitle(tr("Clash coexistence"));
    languageLabel->setText(tr("Language"));behaviorLabel->setText(tr("When closing the window"));
    const QSignalBlocker blocker(behavior);
    behavior->setItemText(0,tr("Keep running in the system tray"));behavior->setItemText(1,tr("Disconnect and exit"));
    autoStart->setText(tr("Launch at sign-in"));silentStart->setText(tr("Start in the background"));
    QString explanation=tr("Changes save automatically.");
    if (!SavedConnectionStore::supportsLanguage(SavedConnectionStore().language()))
        explanation+='\n'+tr("The saved language is invalid. English is being used.");
    else if (!QSystemTrayIcon::isSystemTrayAvailable())
        explanation+='\n'+tr("No system tray is available. Use Exit in the application menu to quit.");
    hint->setText(explanation);
    controller->setText(tr("Choose instance…"));
    if (errorText) error->setText(tr(errorText));
    else if (!error->isHidden()) error->setText(PresentationHelpers::platformOperationMessage(operationError));
}
void ApplicationPreferencesWidget::changeEvent(QEvent *event) {
    QWidget::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) retranslate();
}
