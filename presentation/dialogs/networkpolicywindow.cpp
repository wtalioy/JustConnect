#include "networkpolicywindow.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/localizeddialog.h"
#include "application/networkpolicysession.h"
#include <QDialogButtonBox>
#include <QEvent>
#include <QIcon>
#include <QStyle>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QInputDialog>
#include <QLabel>
#include <QMap>
#include <QPushButton>
#include <QTabWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {
QJsonObject at(const QJsonArray &items, const QJsonValue &index)
{
    const auto i = index.toInteger(-1);
    return i >= 0 && i < items.size() ? items[int(i)].toObject() : QJsonObject{};
}
QString interfaceName(const QJsonObject &network, qint64 index)
{
    for (const auto &value : network["interfaces"].toArray()) {
        const auto item = value.toObject();
        if (item["index"].toInteger(-1) == index) return item["name"].toString();
    }
    return {};
}
QString originalSource(const QJsonObject &network, const QJsonObject &source)
{
    const auto kind = source["kind"].toString();
    if (kind == "loopback") return NetworkPolicyWindow::tr("Loopback");
    if (kind == "interface_address") {
        const auto item = at(network["interfaces"].toArray(), source["interface"]);
        QString name = item["name"].toString();
        if (item["up"].isBool() && !item["up"].toBool()) name += NetworkPolicyWindow::tr(" (inactive)");
        return NetworkPolicyWindow::tr("Interface: %1").arg(name);
    }
    if (kind == "route") {
        const auto route = at(network["routes"].toArray(), source["route"]);
        const auto name = interfaceName(network, route["interface_index"].toInteger());
        return name.isEmpty() ? NetworkPolicyWindow::tr("Route") : NetworkPolicyWindow::tr("Route")+QStringLiteral(": ")+name;
    }
    return NetworkPolicyWindow::tr("Source unavailable");
}
QString campusSource(const QJsonObject &resources, const QJsonObject &conflict)
{
    const auto kind = conflict["kind"].toString();
    if (kind == "ip_resource") {
        const auto item = at(resources["ip_resources"].toArray(), conflict["resource"]);
        QString ip = item["ip_min"].toString();
        if (item["ip_max"] != item["ip_min"]) ip += QStringLiteral("—") + item["ip_max"].toString();
        QString protocol = item["protocol"].toString().toUpper();
        if (protocol == "ALL") protocol = NetworkPolicyWindow::tr("All protocols");
        QString port = QString::number(item["port_min"].toInt());
        if (item["port_min"] != item["port_max"]) port += QStringLiteral("—") + QString::number(item["port_max"].toInt());
        return NetworkPolicyWindow::tr("%1, %2, port %3").arg(ip, protocol, port);
    }
    if (kind == "dns_record") {
        const auto domain = conflict["domain"].toString();
        const auto records = resources["dns_records"].toObject()[domain].toArray();
        const auto i = conflict["record"].toInteger(-1);
        const auto address = i >= 0 && i < records.size() ? records[int(i)].toString() : QString();
        return NetworkPolicyWindow::tr("Published DNS: %1 → %2").arg(domain, address);
    }
    if (kind == "campus_dns") {
        QString label = NetworkPolicyWindow::tr("Campus DNS: %1").arg(resources["campus_dns"].toString());
        if (!resources["campus_dns_enabled"].toBool()) label += NetworkPolicyWindow::tr(" (off)");
        return label;
    }
    return NetworkPolicyWindow::tr("Resource unavailable");
}
QString dnsSource(const QJsonObject &model, const QJsonObject &source)
{
    const auto provider = source["provider"].toString();
    const auto network = model["network"].toObject(), dns = model["dns"].toObject();
    if (provider == "nrpt") return NetworkPolicyWindow::tr("Effective system name rule %1").arg(source["row"].toInteger() + 1);
    if (provider == "global") return NetworkPolicyWindow::tr("System search list");
    if (provider == "clients") {
        const auto row = at(dns["clients"].toArray(), source["row"]);
        const auto index = row["InterfaceIndex"].toInteger();
        return NetworkPolicyWindow::tr("Interface: %1 (%2)").arg(interfaceName(network, index)).arg(index);
    }
    if (provider == "dynamic_store") {
        const auto key = source["key"].toString();
        return (key.startsWith("State:") ? NetworkPolicyWindow::tr("Active DNS: ") : NetworkPolicyWindow::tr("Stored DNS: ")) + key;
    }
    if (provider == "macos_resolver") {
        const auto row = at(dns["macos_resolvers"].toArray(),source["row"]);
        QString scope = NetworkPolicyWindow::tr("Ordinary queries");
        if (row["scope"] == "interface") scope = NetworkPolicyWindow::tr("Interface queries: %1 (%2)")
            .arg(interfaceName(network,source["interface_index"].toInteger())).arg(source["interface_index"].toInteger());
        else if (row["scope"] == "service") scope = NetworkPolicyWindow::tr("Service queries");
        return NetworkPolicyWindow::tr("Effective resolver %1; %2").arg(row["resolver"].toInteger()).arg(scope);
    }
    return NetworkPolicyWindow::tr("Source unavailable");
}
QString dnsRole(const QString &role)
{
    if (role == "search") return NetworkPolicyWindow::tr("Search suffix");
    if (role == "route") return NetworkPolicyWindow::tr("Routed domain");
    if (role == "nrpt") return NetworkPolicyWindow::tr("System name rule (native expression)");
    if (role == "search_configuration") return NetworkPolicyWindow::tr("Search suffix configuration");
    if (role == "match_configuration") return NetworkPolicyWindow::tr("Name matching configuration");
    if (role == "domain_configuration") return NetworkPolicyWindow::tr("Primary domain configuration");
    return NetworkPolicyWindow::tr("Unknown role");
}
QString nameRule(const QJsonObject &rule)
{
    const auto kind = rule["kind"].toString(), value = rule["value"].toString();
    if (kind == "suffix") return NetworkPolicyWindow::tr("%1 (including subdomains)").arg(value);
    if (kind == "exact") return NetworkPolicyWindow::tr("%1 (exact name)").arg(value);
    if (kind == "prefix") return NetworkPolicyWindow::tr("%1* (name prefix)").arg(value);
    if (kind == "single_label") return NetworkPolicyWindow::tr("Single-label name (search suffix)");
    return NetworkPolicyWindow::tr("Unknown name rule");
}
}

NetworkPolicyWindow::NetworkPolicyWindow(NetworkPolicySession *input, QWidget *parent)
    : QDialog(parent), session(input), status(new QLabel(this)), targets(new QTreeWidget(this)), namespaces(new QTreeWidget(this))
{
    resize(760, 560);
    setMinimumSize(480,400);
    status->setObjectName("networkPolicyStatus");
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    targets->setObjectName("networkPolicyTargets");
    targets->setRootIsDecorated(false);
    targets->setWordWrap(true);
    targets->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    targets->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    targets->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    targets->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    namespaces->setObjectName("networkPolicyDnsNamespaces");
    namespaces->setRootIsDecorated(false);
    namespaces->setWordWrap(true);
    namespaces->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    namespaces->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    namespaces->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    namespaces->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    auto *addressPage = new QWidget(this);
    auto *addressLayout = new QVBoxLayout(addressPage);
    addressLayout->setContentsMargins(0, 0, 0, 0);
    addressLayout->setSpacing(12);
    addressLayout->addWidget(targets);
    auto *actions = new QHBoxLayout;
    actions->setSpacing(8);
    campus = new QPushButton(addressPage);
    original = new QPushButton(addressPage);
    campus->setObjectName("chooseCampusAddress");
    original->setObjectName("restoreOriginalAddress");
    actions->addWidget(campus);
    actions->addWidget(original);
    actions->addStretch();
    addressLayout->addLayout(actions);
    policyMessage = new QLabel(this);
    policyMessage->setObjectName("networkPolicyPreferenceStatus");
    policyMessage->setTextFormat(Qt::PlainText);
    policyMessage->setWordWrap(true);
    auto *namePage = new QWidget(this);
    auto *nameLayout = new QVBoxLayout(namePage);
    nameLayout->setContentsMargins(0, 0, 0, 0);
    nameLayout->setSpacing(12);
    nameLayout->addWidget(namespaces);
    nameChoices = new QLabel(namePage);
    nameChoices->setObjectName("networkPolicyCampusNames");
    nameChoices->setTextFormat(Qt::PlainText);
    nameChoices->setWordWrap(true);
    nameLayout->addWidget(nameChoices);
    auto *nameActions = new QHBoxLayout;
    nameActions->setSpacing(8);
    campusName = new QPushButton(namePage);
    originalName = new QPushButton(namePage);
    for (auto *button:{campus,campusName}) {button->setAutoDefault(false);PresentationHelpers::setButtonIcon(button,":/resource/school.svg");}
    for (auto *button:{original,originalName}) {button->setAutoDefault(false);PresentationHelpers::setButtonIcon(button,":/resource/network.svg");}
    campusName->setObjectName("chooseCampusName");
    originalName->setObjectName("restoreOriginalName");
    nameActions->addWidget(campusName);
    nameActions->addWidget(originalName);
    nameActions->addStretch();
    nameLayout->addLayout(nameActions);
    tabs = new QTabWidget(this);
    tabs->addTab(addressPage, QString());
    tabs->addTab(namePage, QString());
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close,this);
    refresh = buttons->addButton(QString(), QDialogButtonBox::ActionRole);
    refresh->setObjectName("refreshNetworkPolicy");
    refresh->setIcon(QIcon(":/resource/refresh.svg"));refresh->setIconSize(QSize(18,18));refresh->setProperty("iconOnly",true);refresh->setAutoDefault(false);refresh->setFlat(true);
    refresh->style()->unpolish(refresh);refresh->style()->polish(refresh);
    explanation = new QLabel(this);
    explanation->setWordWrap(true);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(24,24,24,24);
    layout->setSpacing(16);
    layout->addWidget(status);
    layout->addWidget(tabs);
    layout->addWidget(policyMessage);
    layout->addWidget(explanation);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(refresh, &QPushButton::clicked, this, [this] { if (session) session->refresh(); });
    connect(campus, &QPushButton::clicked, this, &NetworkPolicyWindow::chooseCampusAddress);
    connect(original, &QPushButton::clicked, this, &NetworkPolicyWindow::restoreOriginalAddress);
    connect(campusName, &QPushButton::clicked, this, [this] { editName(true); });
    connect(originalName, &QPushButton::clicked, this, [this] { editName(false); });
    connect(targets, &QTreeWidget::currentItemChanged, this, &NetworkPolicyWindow::updateActions);
    connect(input, &NetworkPolicySession::changed, this, [this] {
        inputErrorText=nullptr;updateModel(); updateActions(); updatePolicyMessage();
    });
    connect(input, &QObject::destroyed, this, [this] {
        if (editor) editor->reject();
        updateModel(); updateActions(); updatePolicyMessage(); reject();
    });
    retranslate();
    updateModel(); updateActions(); updatePolicyMessage();
}

void NetworkPolicyWindow::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if(event->type()==QEvent::LanguageChange){
        retranslate();updateModel();updateActions();updatePolicyMessage();
    }
}
void NetworkPolicyWindow::retranslate()
{
    setWindowTitle(tr("Network protection"));
    targets->setHeaderLabels({tr("Original network"),tr("Source"),tr("Campus overlap"),tr("Campus exceptions")});
    namespaces->setHeaderLabels({tr("Name or expression"),tr("Role"),tr("Source"),tr("Name matching")});
    campus->setText(tr("Use campus…"));original->setText(tr("Use original…"));
    campusName->setText(tr("Use campus…"));originalName->setText(tr("Use original…"));
    tabs->setTabText(0,tr("Addresses"));tabs->setTabText(1,tr("DNS sources"));
    refresh->setToolTip(tr("Refresh"));refresh->setAccessibleName(tr("Refresh"));
    explanation->setText(tr("Refreshing only reads the network. Choices do not expand school authorization. Switching sides may interrupt existing connections; a target cannot use both sides at once."));
}
QInputDialog *NetworkPolicyWindow::createEditor(std::function<void(QInputDialog *)> translate)
{
    auto *input=new LocalizedDialog<QInputDialog>(this);editor=input;
    input->setTranslation([input,translate=std::move(translate)]{translate(input);});
    input->setAttribute(Qt::WA_DeleteOnClose);input->setWindowModality(Qt::WindowModal);
    input->setMinimumWidth(320);input->resize(440,input->sizeHint().height());
    connect(input,&QDialog::finished,this,[this,input]{
        if(editor==input)editor=nullptr;updateActions();
    });
    return input;
}
void NetworkPolicyWindow::setInputError(const char *source,const QString &scope)
{
    inputErrorText=source;inputErrorScope=scope;updatePolicyMessage();
}

void NetworkPolicyWindow::updateActions()
{
    const auto *selected = targets->currentItem();
    const auto subnet = QHostAddress::parseSubnet(selected ? selected->text(0) : QString());
    campus->setEnabled(session && !editor && session->status() == CoreEngine::RequestStatus::Success
        && !session->isBusy() && session->model()["schema_version"].toInteger() > 0
        && subnet.first.protocol() == QAbstractSocket::IPv4Protocol);
    original->setEnabled(session && !editor && !session->currentGeneration().isEmpty()
        && !session->isPolicyUpdating() && !session->campusAddresses().isEmpty());
    campusName->setEnabled(session && !editor && session->status() == CoreEngine::RequestStatus::Success
        && !session->isBusy() && session->model()["schema_version"].toInteger() > 0
        && !session->model()["name_targets"].toArray().isEmpty());
    originalName->setEnabled(session && !editor && !session->currentGeneration().isEmpty()
        && !session->isPolicyUpdating() && !session->campusNames().isEmpty());
}

void NetworkPolicyWindow::updatePolicyMessage()
{
    using Status = CoreEngine::RequestStatus;
    nameChoices->clear();
    if (!session || session->currentGeneration().isEmpty()) { policyMessage->clear(); return; }
    QStringList names;
    for (const auto &value : session->campusNames()) names.append(value.toString());
    nameChoices->setText(names.isEmpty() ? NetworkPolicyWindow::tr("No confirmed campus name exceptions.")
        : NetworkPolicyWindow::tr("Campus name exceptions: %1").arg(names.join(QStringLiteral(", "))));
    if(inputErrorText){policyMessage->setText(inputErrorScope.isEmpty() ? tr(inputErrorText) : tr(inputErrorText).arg(inputErrorScope));return;}
    const auto count = session->campusAddresses().size();
    QString text = NetworkPolicyWindow::tr("Confirmed: %1 campus IPv4 and %2 name exceptions.").arg(count).arg(names.size());
    const auto result = session->policyStatus();
    if (session->isPolicyUpdating()) text = NetworkPolicyWindow::tr("Confirming campus choices. ") + text;
    else if (result == Status::Pending) text = NetworkPolicyWindow::tr("The connection is busy. Try again shortly. ") + text;
    else if (result == Status::Invalid) text = NetworkPolicyWindow::tr("Invalid choice. Check the protected scope and exact address or name. ") + text;
    else if (result == Status::Unavailable) text = NetworkPolicyWindow::tr("Campus choices cannot be updated for this connection. ") + text;
    else if (result && result != Status::Success) text = NetworkPolicyWindow::tr("Campus choices could not be applied. Check the connection and retry. ") + text;
    policyMessage->setText(text);
}

void NetworkPolicyWindow::chooseCampusAddress()
{
    if (!campus->isEnabled() || !session || !targets->currentItem()) return;
    const auto id = session->currentGeneration(), prefix = targets->currentItem()->text(0);
    auto *input = createEditor([this,prefix](QInputDialog *input) {
        input->setWindowTitle(NetworkPolicyWindow::tr("Use campus address"));
        input->setLabelText(NetworkPolicyWindow::tr("One IPv4 address in %1:\nThe same address cannot use both networks. School authorization still applies.").arg(prefix));
    });
    connect(input, &QInputDialog::textValueSelected, this, [this, id, prefix](const QString &value) {
        if (!session || session->currentGeneration() != id) return;
        const auto text = value.trimmed();
        const QHostAddress address(text);
        if (address.protocol() != QAbstractSocket::IPv4Protocol || address.toString() != text
            || !address.isInSubnet(QHostAddress::parseSubnet(prefix))) {
            setInputError(QT_TR_NOOP("Enter a complete IPv4 address in %1. Nothing was changed."),prefix);
            return;
        }
        if (!session->setCampusAddress(text, true))
            setInputError(QT_TR_NOOP("This choice cannot be applied. Check the network results and retry."));
    });
    input->open();
    updateActions();
}

void NetworkPolicyWindow::restoreOriginalAddress()
{
    if (!original->isEnabled() || !session) return;
    const auto id = session->currentGeneration();
    QStringList addresses;
    for (const auto &value : session->campusAddresses()) addresses.append(value.toString());
    auto *input = createEditor([this](QInputDialog *input) {
        input->setWindowTitle(NetworkPolicyWindow::tr("Use original network"));
        input->setLabelText(NetworkPolicyWindow::tr("Choose the campus address exception to remove:"));
    });
    input->setComboBoxItems(addresses);
    input->setComboBoxEditable(false);
    connect(input, &QInputDialog::textValueSelected, this, [this, id](const QString &value) {
        if (!session || session->currentGeneration() != id) return;
        if (!session->setCampusAddress(value, false))
            setInputError(QT_TR_NOOP("This address cannot be restored now. Try again shortly."));
    });
    input->open();
    updateActions();
}

void NetworkPolicyWindow::editName(bool campus)
{
    if (!session || !(campus ? campusName : originalName)->isEnabled()) return;
    const auto id = session->currentGeneration();
    auto *input = createEditor([this,campus](QInputDialog *input) {
        input->setWindowTitle(campus ? NetworkPolicyWindow::tr("Use campus name") : NetworkPolicyWindow::tr("Use original name"));
        if (campus) {
            input->setLabelText(NetworkPolicyWindow::tr("One protected name to use through campus:\nWildcards and whole scopes are not accepted. School authorization still applies."));
        } else {
            input->setLabelText(NetworkPolicyWindow::tr("Choose the campus name exception to remove:"));
        }
    });
    if(!campus){
        QStringList names;for(const auto &value:session->campusNames())names.append(value.toString());
        input->setComboBoxItems(names);input->setComboBoxEditable(false);
    }
    connect(input, &QInputDialog::textValueSelected, this, [this, id, campus](const QString &value) {
        if (!session || session->currentGeneration() != id) return;
        if (!session->setCampusName(value.trimmed(), campus))
            setInputError(QT_TR_NOOP("This name choice cannot be applied. Check the full name and network results, then retry."));
    });
    input->open();
    updateActions();
}

void NetworkPolicyWindow::updateModel()
{
    const auto selected = targets->currentItem() ? targets->currentItem()->text(0) : QString();
    if (!session || displayedModel["generation"] != session->currentGeneration()
        || (session->status() != CoreEngine::RequestStatus::Pending && session->status() != CoreEngine::RequestStatus::Success)) {
        displayedModel = {};
        PresentationHelpers::setTreeRows(targets,{});
        PresentationHelpers::setTreeRows(namespaces,{});
    }
    if (editor && (!session || session->status() == CoreEngine::RequestStatus::Stale)) editor->reject();
    refresh->setEnabled(false);
    if (!session) { status->setText(NetworkPolicyWindow::tr("The connection has ended.")); return; }
    using Status = CoreEngine::RequestStatus;
    const auto result = session->status();
    if (result == Status::Stale) { status->setText(NetworkPolicyWindow::tr("The connection has ended.")); return; }
    if (result == Status::Unavailable) { status->setText(NetworkPolicyWindow::tr("No complete network results. Connect first, or check that network inspection is supported.")); return; }
    refresh->setEnabled(!session->isBusy());
    if (result == Status::Pending) {
        status->setText(NetworkPolicyWindow::tr("Reading original networks and campus resources…"));
        if (displayedModel.isEmpty()) return;
    } else if (result == Status::Success) displayedModel = session->model();
    else { status->setText(NetworkPolicyWindow::tr("Could not read complete network information. Refresh to retry.")); return; }
    // Keep raw display data so language changes can translate retained rows during a refresh.
    const auto &model = displayedModel;
    const auto network = model["network"].toObject(), resources = model["resources"].toObject();
    const auto scopes = model["targets"].toArray(), conflicts = model["conflicts"].toArray();
    QMap<int, QStringList> overlapText;
    QList<QStringList> targetRows,dnsRows;
    for (const auto &value : conflicts) {
        const auto conflict = value.toObject();
        const int index = conflict["target"].toInt(-1);
        if (index >= 0 && index < scopes.size()) overlapText[index].append(campusSource(resources, conflict));
    }
    for (int i = 0; i < scopes.size(); ++i) {
        const auto scope = scopes[i].toObject();
        QStringList origins;
        for (const auto &source : scope["sources"].toArray()) origins.append(originalSource(network, source.toObject()));
        origins.removeDuplicates();
        auto overlaps = overlapText.value(i);
        overlaps.removeDuplicates();
        QStringList exceptions;
        for (const auto &address : session->campusAddresses())
            if (QHostAddress(address.toString()).isInSubnet(QHostAddress::parseSubnet(scope["prefix"].toString())))
                exceptions.append(address.toString() + "/32");
        targetRows.append(QStringList{scope["prefix"].toString(), origins.join('\n'), overlaps.join('\n'), exceptions.join('\n')});
    }
    if(PresentationHelpers::setTreeRows(targets,targetRows)) {
        targets->setCurrentItem(nullptr);
        for(int i=0;i<targets->topLevelItemCount();++i)
            if(targets->topLevelItem(i)->text(0)==selected) targets->setCurrentItem(targets->topLevelItem(i));
    }
    const auto domains = model["dns_namespaces"].toArray();
    QMap<int, QStringList> namePatterns;
    QJsonArray reservedNames;
    for (const auto &value : model["name_targets"].toArray()) {
        const auto rule = value.toObject();
        bool reserved = false;
        for (const auto &source : rule["sources"].toArray()) {
            const auto origin = source.toObject();
            if (origin["kind"] == "namespace") namePatterns[origin["index"].toInt(-1)].append(nameRule(rule));
            reserved |= origin["kind"] == "loopback";
        }
        if (reserved) reservedNames.append(rule);
    }
    for (int i = 0; i < domains.size(); ++i) {
        const auto item = domains[i].toObject();
        auto name = item["name"].toString();
        if (name.isEmpty() || name == ".") name = NetworkPolicyWindow::tr("Default query scope (root)");
        dnsRows.append(QStringList{name, dnsRole(item["role"].toString()), dnsSource(model, item["source"].toObject()), namePatterns.value(i).join('\n')});
    }
    for (const auto &value : reservedNames) {
        const auto rule = value.toObject();
        dnsRows.append(QStringList{rule["value"].toString(), NetworkPolicyWindow::tr("System reserved name"), NetworkPolicyWindow::tr("Loopback"), nameRule(rule)});
    }
    PresentationHelpers::setTreeRows(namespaces,dnsRows);
    if (result == Status::Success)
        status->setText(NetworkPolicyWindow::tr("%1 original scopes · %2 campus overlaps · %3 DNS sources")
            .arg(scopes.size()).arg(conflicts.size()).arg(namespaces->topLevelItemCount()));
}
