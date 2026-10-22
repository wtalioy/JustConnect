#include "networkpolicywindow.h"
#include "application/networkpolicysession.h"
#include <QDialogButtonBox>
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
    if (kind == "loopback") return QStringLiteral("回环");
    if (kind == "interface_address") {
        const auto item = at(network["interfaces"].toArray(), source["interface"]);
        QString name = item["name"].toString();
        if (item["up"].isBool() && !item["up"].toBool()) name += QStringLiteral("（未启用）");
        return QStringLiteral("接口：%1").arg(name);
    }
    if (kind == "route") {
        const auto route = at(network["routes"].toArray(), source["route"]);
        QStringList names;
        names.append(interfaceName(network, route["interface_index"].toInteger()));
        for (const auto &hop : route["next_hops"].toArray())
            names.append(interfaceName(network, hop.toObject()["interface_index"].toInteger()));
        names.removeAll(QString());
        names.removeDuplicates();
        QString label = route["table"].toInteger() > 0 ? QStringLiteral("路由表 %1").arg(route["table"].toInteger()) : QStringLiteral("路由记录");
        if (!names.isEmpty()) label += QStringLiteral("：") + names.join(QStringLiteral("、"));
        return label;
    }
    return QStringLiteral("来源信息不可用");
}
QString campusSource(const QJsonObject &resources, const QJsonObject &conflict)
{
    const auto kind = conflict["kind"].toString();
    if (kind == "ip_resource") {
        const auto item = at(resources["ip_resources"].toArray(), conflict["resource"]);
        QString ip = item["ip_min"].toString();
        if (item["ip_max"] != item["ip_min"]) ip += QStringLiteral("—") + item["ip_max"].toString();
        QString protocol = item["protocol"].toString().toUpper();
        if (protocol == "ALL") protocol = QStringLiteral("全部协议");
        QString port = QString::number(item["port_min"].toInt());
        if (item["port_min"] != item["port_max"]) port += QStringLiteral("—") + QString::number(item["port_max"].toInt());
        return QStringLiteral("%1，%2，端口 %3").arg(ip, protocol, port);
    }
    if (kind == "dns_record") {
        const auto domain = conflict["domain"].toString();
        const auto records = resources["dns_records"].toObject()[domain].toArray();
        const auto i = conflict["record"].toInteger(-1);
        const auto address = i >= 0 && i < records.size() ? records[int(i)].toString() : QString();
        return QStringLiteral("内置解析：%1 → %2").arg(domain, address);
    }
    if (kind == "campus_dns") {
        QString label = QStringLiteral("校园 DNS：%1").arg(resources["campus_dns"].toString());
        if (!resources["campus_dns_enabled"].toBool()) label += QStringLiteral("（当前关闭）");
        return label;
    }
    return QStringLiteral("资源信息不可用");
}
QString dnsSource(const QJsonObject &model, const QJsonObject &source)
{
    const auto provider = source["provider"].toString();
    const auto network = model["network"].toObject(), dns = model["dns"].toObject();
    if (provider == "resolv_conf") return QStringLiteral("解析器文件：%1，第 %2 行")
        .arg(dns["resolv_conf"].toObject()["path"].toString()).arg(source["line"].toInteger() + 1);
    if (provider == "resolved") {
        const auto index = source["interface_index"].toInteger();
        return index == 0 ? QStringLiteral("系统解析服务：全局")
            : QStringLiteral("系统解析服务：%1（%2）").arg(interfaceName(network, index)).arg(index);
    }
    if (provider == "nrpt") return QStringLiteral("生效的系统名称规则 %1").arg(source["row"].toInteger() + 1);
    if (provider == "global") return QStringLiteral("系统搜索列表");
    if (provider == "clients") {
        const auto row = at(dns["clients"].toArray(), source["row"]);
        const auto index = row["InterfaceIndex"].toInteger();
        return QStringLiteral("接口：%1（%2）").arg(interfaceName(network, index)).arg(index);
    }
    if (provider == "dynamic_store") {
        const auto key = source["key"].toString();
        return (key.startsWith("State:") ? QStringLiteral("当前 DNS 配置：") : QStringLiteral("已保存 DNS 配置：")) + key;
    }
    return QStringLiteral("来源信息不可用");
}
QString dnsRole(const QString &role)
{
    if (role == "search") return QStringLiteral("搜索后缀");
    if (role == "route") return QStringLiteral("路由域");
    if (role == "search_route") return QStringLiteral("搜索后缀及路由域");
    if (role == "nrpt") return QStringLiteral("系统名称规则（原生表达式）");
    if (role == "search_configuration") return QStringLiteral("搜索后缀配置");
    if (role == "match_configuration") return QStringLiteral("名称匹配配置");
    if (role == "domain_configuration") return QStringLiteral("主域配置");
    return QStringLiteral("用途未知");
}
QString nameRule(const QJsonObject &rule)
{
    const auto kind = rule["kind"].toString(), value = rule["value"].toString();
    if (kind == "suffix") return QStringLiteral("%1（含子域）").arg(value);
    if (kind == "exact") return QStringLiteral("%1（完整名称）").arg(value);
    if (kind == "prefix") return QStringLiteral("%1*（名称前缀）").arg(value);
    if (kind == "single_label") return QStringLiteral("无点名称（搜索后缀）");
    return QStringLiteral("未知名称规则");
}
}

NetworkPolicyWindow::NetworkPolicyWindow(NetworkPolicySession *input, QWidget *parent)
    : QDialog(parent), session(input), status(new QLabel(this)), targets(new QTreeWidget(this)), namespaces(new QTreeWidget(this))
{
    setWindowTitle(QStringLiteral("网络范围与校园地址重叠"));
    resize(920, 560);
    status->setObjectName("networkPolicyStatus");
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    targets->setObjectName("networkPolicyTargets");
    targets->setRootIsDecorated(false);
    targets->setHeaderLabels({QStringLiteral("原网络范围"), QStringLiteral("来源"), QStringLiteral("重叠的校园地址"), QStringLiteral("已确认的校园例外")});
    targets->setWordWrap(true);
    targets->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    targets->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    targets->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    targets->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    namespaces->setObjectName("networkPolicyDnsNamespaces");
    namespaces->setRootIsDecorated(false);
    namespaces->setHeaderLabels({QStringLiteral("名称／表达式"), QStringLiteral("用途"), QStringLiteral("来源"), QStringLiteral("名称规则模型")});
    namespaces->setWordWrap(true);
    namespaces->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    namespaces->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    namespaces->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    namespaces->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    auto *addressPage = new QWidget(this);
    auto *addressLayout = new QVBoxLayout(addressPage);
    addressLayout->setContentsMargins(0, 0, 0, 0);
    addressLayout->addWidget(targets);
    auto *actions = new QHBoxLayout;
    campus = new QPushButton(QStringLiteral("选择校园地址…"), addressPage);
    original = new QPushButton(QStringLiteral("恢复原网络…"), addressPage);
    campus->setObjectName("chooseCampusAddress");
    original->setObjectName("restoreOriginalAddress");
    actions->addWidget(campus);
    actions->addWidget(original);
    actions->addStretch();
    addressLayout->addLayout(actions);
    policyMessage = new QLabel(addressPage);
    policyMessage->setObjectName("networkPolicyPreferenceStatus");
    policyMessage->setTextFormat(Qt::PlainText);
    policyMessage->setWordWrap(true);
    addressLayout->addWidget(policyMessage);
    auto *tabs = new QTabWidget(this);
    tabs->addTab(addressPage, QStringLiteral("地址范围"));
    tabs->addTab(namespaces, QStringLiteral("DNS 名称与来源"));
    auto *buttons = new QDialogButtonBox(this);
    refresh = buttons->addButton(QStringLiteral("刷新"), QDialogButtonBox::ActionRole);
    refresh->setObjectName("refreshNetworkPolicy");
    buttons->addButton(QStringLiteral("关闭"), QDialogButtonBox::RejectRole);
    auto *explanation = new QLabel(QStringLiteral("这里展示最近读取的模型，刷新不自动应用；实际访问按核心已确认策略及学校授权判断。"), this);
    explanation->setWordWrap(true);
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(status);
    layout->addWidget(tabs);
    layout->addWidget(explanation);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(refresh, &QPushButton::clicked, this, [this] { if (session) session->refresh(); });
    connect(campus, &QPushButton::clicked, this, &NetworkPolicyWindow::chooseCampusAddress);
    connect(original, &QPushButton::clicked, this, &NetworkPolicyWindow::restoreOriginalAddress);
    connect(targets, &QTreeWidget::currentItemChanged, this, &NetworkPolicyWindow::updateActions);
    connect(input, &NetworkPolicySession::changed, this, [this] {
        updateModel(); updateActions(); updatePolicyMessage();
    });
    connect(input, &QObject::destroyed, this, [this] {
        if (editor) editor->reject();
        updateModel(); updateActions(); updatePolicyMessage(); reject();
    });
    updateModel(); updateActions(); updatePolicyMessage();
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
}

void NetworkPolicyWindow::updatePolicyMessage()
{
    using Status = CoreEngine::RequestStatus;
    if (!session || session->currentGeneration().isEmpty()) { policyMessage->clear(); return; }
    const auto count = session->campusAddresses().size();
    QString text = QStringLiteral("已确认 %1 个校园例外。仅对单个 IPv4 地址生效，仍需学校授权；相同地址不能同时访问两侧。").arg(count);
    const auto result = session->policyStatus();
    if (session->isPolicyUpdating()) text = QStringLiteral("正在确认地址选择，原选择仍有效。") + text;
    else if (result == Status::Pending) text = QStringLiteral("核心正忙，可以稍后重试。") + text;
    else if (result == Status::Invalid) text = QStringLiteral("地址选择无效，请检查范围和完整 IPv4 地址。") + text;
    else if (result == Status::Unavailable) text = QStringLiteral("当前核心无法更新地址选择。") + text;
    else if (result && result != Status::Success) text = QStringLiteral("地址选择未能应用，仍保留最后确认的选择，可以重试。") + text;
    policyMessage->setText(text);
}

void NetworkPolicyWindow::chooseCampusAddress()
{
    if (!campus->isEnabled() || !session || !targets->currentItem()) return;
    const auto id = session->currentGeneration(), prefix = targets->currentItem()->text(0);
    auto *input = new QInputDialog(this);
    editor = input;
    input->setAttribute(Qt::WA_DeleteOnClose);
    input->setWindowModality(Qt::WindowModal);
    input->setWindowTitle(QStringLiteral("选择校园地址"));
    input->setLabelText(QStringLiteral("请输入 %1 内需要改走校园的单个 IPv4 地址：\n相同地址不能同时访问两侧，业务仍需学校授权。").arg(prefix));
    input->setOkButtonText(QStringLiteral("选择校园侧"));
    connect(input, &QInputDialog::textValueSelected, this, [this, id, prefix](const QString &value) {
        if (!session || session->currentGeneration() != id) return;
        const auto text = value.trimmed();
        const QHostAddress address(text);
        if (address.protocol() != QAbstractSocket::IPv4Protocol || address.toString() != text
            || !address.isInSubnet(QHostAddress::parseSubnet(prefix))) {
            policyMessage->setText(QStringLiteral("请输入 %1 内的完整 IPv4 地址，未改变原选择。").arg(prefix));
            return;
        }
        if (!session->setCampusAddress(text, true))
            policyMessage->setText(QStringLiteral("当前无法应用这个选择，请检查网络结果并重试。"));
    });
    connect(input, &QDialog::finished, this, [this, input] { if (editor == input) editor = nullptr; updateActions(); });
    input->open();
    updateActions();
}

void NetworkPolicyWindow::restoreOriginalAddress()
{
    if (!original->isEnabled() || !session) return;
    const auto id = session->currentGeneration();
    QStringList addresses;
    for (const auto &value : session->campusAddresses()) addresses.append(value.toString());
    auto *input = new QInputDialog(this);
    editor = input;
    input->setAttribute(Qt::WA_DeleteOnClose);
    input->setWindowModality(Qt::WindowModal);
    input->setWindowTitle(QStringLiteral("恢复原网络"));
    input->setLabelText(QStringLiteral("请选择要撤回校园例外的地址："));
    input->setComboBoxItems(addresses);
    input->setComboBoxEditable(false);
    input->setOkButtonText(QStringLiteral("恢复原网络"));
    connect(input, &QInputDialog::textValueSelected, this, [this, id](const QString &value) {
        if (!session || session->currentGeneration() != id) return;
        if (!session->setCampusAddress(value, false))
            policyMessage->setText(QStringLiteral("当前无法恢复这个地址，请稍后重试。"));
    });
    connect(input, &QDialog::finished, this, [this, input] { if (editor == input) editor = nullptr; updateActions(); });
    input->open();
    updateActions();
}

void NetworkPolicyWindow::updateModel()
{
    const auto selected = targets->currentItem() ? targets->currentItem()->text(0) : QString();
    targets->clear();
    namespaces->clear();
    if (editor && (!session || session->status() == CoreEngine::RequestStatus::Stale)) editor->reject();
    refresh->setEnabled(false);
    if (!session) { status->setText(QStringLiteral("连接已结束。")); return; }
    using Status = CoreEngine::RequestStatus;
    const auto result = session->status();
    if (result == Status::Stale) { status->setText(QStringLiteral("连接已结束。")); return; }
    if (result == Status::Unavailable) { status->setText(QStringLiteral("当前没有完整的网络检查结果。请先连接，或确认系统支持读取网络信息。")); return; }
    refresh->setEnabled(!session->isBusy());
    if (result == Status::Pending) { status->setText(QStringLiteral("正在读取原网络与校园资源…")); return; }
    if (result != Status::Success) { status->setText(QStringLiteral("网络信息无法完整读取或表示，可以刷新重试。")); return; }
    const auto model = session->model();
    const auto network = model["network"].toObject(), resources = model["resources"].toObject();
    const auto scopes = model["targets"].toArray(), conflicts = model["conflicts"].toArray();
    QMap<int, QStringList> overlapText;
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
        auto *row = new QTreeWidgetItem(targets, {scope["prefix"].toString(), origins.join('\n'), overlaps.join('\n'), exceptions.join('\n')});
        for (int column=1; column<targets->columnCount(); ++column) row->setToolTip(column, row->text(column));
        if (scope["prefix"].toString() == selected) targets->setCurrentItem(row);
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
        if (name.isEmpty() || name == ".") name = QStringLiteral("默认查询范围（根域）");
        auto *row = new QTreeWidgetItem(namespaces, {name, dnsRole(item["role"].toString()), dnsSource(model, item["source"].toObject()), namePatterns.value(i).join('\n')});
        for (int column = 0; column < namespaces->columnCount(); ++column) row->setToolTip(column, row->text(column));
    }
    for (const auto &value : reservedNames) {
        const auto rule = value.toObject();
        new QTreeWidgetItem(namespaces, {rule["value"].toString(), QStringLiteral("系统保留名称"), QStringLiteral("回环"), nameRule(rule)});
    }
    status->setText(QStringLiteral("检测到 %1 个原网络范围、%2 项校园地址重叠、%3 项 DNS 名称来源。")
        .arg(scopes.size()).arg(conflicts.size()).arg(namespaces->topLevelItemCount()));
}
