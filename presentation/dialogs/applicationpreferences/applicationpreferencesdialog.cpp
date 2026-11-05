#include "applicationpreferencesdialog.h"
#include "presentation/i18n/applicationlanguage.h"
#include "presentation/coordinators/controllerselectioncoordinator.h"
#include "infrastructure/settings/profilemanager.h"
#include <QComboBox>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QSystemTrayIcon>

ApplicationPreferencesDialog::ApplicationPreferencesDialog(QWidget *parent) : QDialog(parent) {
    setObjectName("applicationPreferencesDialog");
    setAttribute(Qt::WA_DeleteOnClose);setWindowModality(Qt::WindowModal);
    auto *layout=new QFormLayout(this);layout->setSpacing(16);layout->setContentsMargins(24,24,24,24);
    layout->setRowWrapPolicy(QFormLayout::WrapAllRows);setMinimumWidth(320);
    language=new QComboBox(this);language->setObjectName("languageComboBox");
    language->addItem("English","en");language->addItem(QString::fromUtf8("简体中文"),"zh_CN");
    language->setCurrentIndex(language->findData(ApplicationLanguage::instance().current()));
    languageLabel=new QLabel(this);languageLabel->setBuddy(language);layout->addRow(languageLabel,language);
    behavior=new QComboBox(this);behavior->setObjectName("closeBehaviorComboBox");
    behavior->addItem(QString(),true);behavior->addItem(QString(),false);
    behavior->setCurrentIndex(ProfileManager().closeToTray()?0:1);
    behaviorLabel=new QLabel(this);behaviorLabel->setBuddy(behavior);layout->addRow(behaviorLabel,behavior);
    hint=new QLabel(this);hint->setWordWrap(true);layout->addRow(hint);
    controller=new QPushButton(this);controller->setObjectName("controllerSettingsButton");layout->addRow(controller);
    auto *selection=new ControllerSelectionCoordinator(this,this);
    connect(controller,&QPushButton::clicked,selection,[this,selection] {
        controller->setEnabled(false);
        selection->choose([this](std::optional<QString>){controller->setEnabled(true);},true);
    });
    error=new QLabel(this);error->setObjectName("preferenceError");error->setWordWrap(true);error->hide();layout->addRow(error);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel,this);layout->addRow(buttons);
    connect(buttons,&QDialogButtonBox::rejected,this,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,this,[this] {
        if (!ApplicationLanguage::instance().savePreferences(language->currentData().toString(),behavior->currentData().toBool())) {
            error->setText(tr("Could not save preferences. Your previous settings are unchanged."));error->show();return;
        }
        accept();
    });
    retranslate();resize(440,sizeHint().height());
}
void ApplicationPreferencesDialog::retranslate() {
    setWindowTitle(tr("Application settings"));
    languageLabel->setText(tr("Language"));behaviorLabel->setText(tr("When closing the window"));
    behavior->setItemText(0,tr("Keep running in the system tray"));behavior->setItemText(1,tr("Disconnect and exit"));
    hint->setText(!ProfileManager::supportsLanguage(ProfileManager().language())
        ? tr("The saved language is invalid. English is being used.")
        : QSystemTrayIcon::isSystemTrayAvailable()
        ? tr("Exit always disconnects and restores your network.")
        : tr("No system tray is available. Closing keeps the window accessible; use Exit to quit."));
    controller->setText(tr("Clash coexistence…"));
}
void ApplicationPreferencesDialog::changeEvent(QEvent *event) {
    QDialog::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) retranslate();
}
