#include "controllerselectioncoordinator.h"
#include <QComboBox>
#include <QIcon>
#include <QStyle>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QtConcurrent>

ControllerSelectionCoordinator::ControllerSelectionCoordinator(QWidget *window,QObject *parent,
    const QString &storageRoot,Reader reader)
    :QObject(parent),window(window),preferences(storageRoot),reader(reader?std::move(reader):EmbeddedCoreEngine::discoverControllers)
{
    connect(&watcher,&QFutureWatcher<EmbeddedCoreEngine::ControllerDiscovery>::finished,this,[this] {
        if (!completion) return;
        if (reading!=request) { read();return; }
        const auto result=watcher.result();
        if (!settings && result.status==CoreEngine::RequestStatus::Success && result.candidates.size()<2
            && preferences.controllerAddress().isEmpty()) { finish(QString());return; }
        showChoice(result);
    });
}
ControllerSelectionCoordinator::~ControllerSelectionCoordinator()
{
    completion={};++request;closeDialog();
}
void ControllerSelectionCoordinator::choose(Completion next,bool showSettings)
{
    cancel();completion=std::move(next);settings=showSettings;
    const auto current=preferences.controllerAddress();
    if (!settings && !current.isEmpty() && EmbeddedCoreEngine::validControllerAddress(current)) { finish(current);return; }
    if (!watcher.isRunning()) read();
}
void ControllerSelectionCoordinator::cancel()
{
    ++request;finish(std::nullopt);
}
void ControllerSelectionCoordinator::closeDialog()
{
    const auto previous=dialog;dialog=nullptr;
    if (previous) { previous->reject();previous->deleteLater(); }
}
void ControllerSelectionCoordinator::finish(std::optional<QString> address)
{
    auto callback=std::move(completion);completion={};closeDialog();
    if (callback) callback(std::move(address));
}
void ControllerSelectionCoordinator::read()
{
    reading=request;watcher.setFuture(QtConcurrent::run(reader));
}
void ControllerSelectionCoordinator::showChoice(const EmbeddedCoreEngine::ControllerDiscovery &result)
{
    closeDialog();
    auto *view=new QDialog(window);dialog=view;
    view->setObjectName("controllerSelectionDialog");view->setWindowTitle(tr("Clash coexistence"));
    view->setWindowModality(Qt::WindowModal);view->setAttribute(Qt::WA_DeleteOnClose);
    auto *layout=new QFormLayout(view);layout->setRowWrapPolicy(QFormLayout::WrapAllRows);
    layout->setContentsMargins(24,24,24,24);layout->setSpacing(12);view->setMinimumWidth(320);
    auto *hint=new QLabel(result.status==CoreEngine::RequestStatus::Success
        ? tr("Choose the local controller to use. Changes apply to the next connection.")
        : tr("Automatic discovery is unavailable. Retry or enter a local controller address."),view);
    hint->setWordWrap(true);layout->addRow(hint);
    auto *choices=new QComboBox(view);choices->setObjectName("controllerChoices");
    choices->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    choices->addItem(tr("Automatically discover"),QString());
    for (const auto &value:result.candidates) {
        const auto item=value.toObject();
        choices->addItem(tr("%1 · PID %2 · %3").arg(item["name"].toString()).arg(item["pid"].toInt()).arg(item["endpoint"].toString()),item["endpoint"].toString());
    }
    const auto manualIndex=choices->count();choices->addItem(tr("Enter local address…"));
    layout->addRow(tr("Controller"),choices);
    auto *address=new QLineEdit(view);address->setObjectName("controllerAddress");
    address->setPlaceholderText(tr("A loopback HTTP(S), unix:// or pipe:// address"));
    auto *addressLabel=new QLabel(tr("Local address"),view);layout->addRow(addressLabel,address);
    const auto current=preferences.controllerAddress();
    int selected=choices->findData(current);
    if (selected<0) {selected=manualIndex;address->setText(current);}
    if (!settings && result.candidates.size()>1 && current.isEmpty()) selected=1;
    choices->setCurrentIndex(selected);
    const auto update=[choices,address,addressLabel,manualIndex] {
        address->setVisible(choices->currentIndex()==manualIndex);
        addressLabel->setVisible(address->isVisibleTo(address->parentWidget()));
        choices->setToolTip(choices->currentData().toString());
    };
    connect(choices,&QComboBox::currentIndexChanged,view,update);update();
    auto *error=new QLabel(view);error->setObjectName("controllerError");error->setWordWrap(true);layout->addRow(error);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,view);
    buttons->button(QDialogButtonBox::Ok)->setText(settings?tr("Save"):tr("Use controller"));
    auto *retry=buttons->addButton(tr("Refresh"),QDialogButtonBox::ActionRole);layout->addRow(buttons);
    retry->setText({});retry->setIcon(QIcon(":/resource/refresh.svg"));retry->setIconSize(QSize(18,18));
    retry->setToolTip(tr("Refresh"));retry->setAccessibleName(tr("Refresh"));retry->setProperty("iconOnly",true);retry->setAutoDefault(false);
    retry->style()->unpolish(retry);retry->style()->polish(retry);
    const auto generation=request;
    connect(view,&QDialog::rejected,this,[this,view,generation] {if (dialog==view && request==generation) finish(std::nullopt);});
    connect(retry,&QPushButton::clicked,this,[this,generation] {if (request!=generation || !completion) return;++request;closeDialog();read();});
    connect(buttons,&QDialogButtonBox::rejected,view,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,this,[this,choices,address,error,manualIndex,generation,result] {
        if (request!=generation || !completion) return;
        if (!settings && choices->currentIndex()==0 && (result.candidates.size()>1 || result.status!=CoreEngine::RequestStatus::Success)) {
            error->setText(tr("Select an instance or enter its local address."));return;
        }
        const bool manual=choices->currentIndex()==manualIndex;
        const auto selected=manual?address->text().trimmed():choices->currentData().toString();
        if ((manual && selected.isEmpty()) || !EmbeddedCoreEngine::validControllerAddress(selected)) {
            error->setText(tr("Enter a local endpoint without credentials, a query or a fragment."));return;
        }
        if (selected!=preferences.controllerAddress() && !preferences.setControllerAddress(selected)) {
            error->setText(tr("The preference could not be saved. Your previous choice is unchanged."));return;
        }
        finish(selected);
    });
    view->resize(520,view->sizeHint().height());view->show();
}
