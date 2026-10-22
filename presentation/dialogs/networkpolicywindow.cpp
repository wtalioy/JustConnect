#include "networkpolicywindow.h"
#include "application/networkpolicysession.h"
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMap>
#include <QPushButton>
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
}

NetworkPolicyWindow::NetworkPolicyWindow(NetworkPolicySession *input, QWidget *parent)
    : QDialog(parent), session(input), status(new QLabel(this)), targets(new QTreeWidget(this))
{
    setWindowTitle(QStringLiteral("网络范围与校园地址重叠"));
    resize(920, 560);
    status->setObjectName("networkPolicyStatus");
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    targets->setObjectName("networkPolicyTargets");
    targets->setRootIsDecorated(false);
    targets->setHeaderLabels({QStringLiteral("原网络范围"), QStringLiteral("来源"), QStringLiteral("重叠的校园地址")});
    targets->setWordWrap(true);
    targets->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    targets->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    targets->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    auto *buttons = new QDialogButtonBox(this);
    refresh = buttons->addButton(QStringLiteral("刷新"), QDialogButtonBox::ActionRole);
    refresh->setObjectName("refreshNetworkPolicy");
    buttons->addButton(QStringLiteral("关闭"), QDialogButtonBox::RejectRole);
    auto *explanation = new QLabel(QStringLiteral("这里展示检测结果。业务访问仍按学校授权的协议和端口判断。"), this);
    explanation->setWordWrap(true);
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(status);
    layout->addWidget(targets);
    layout->addWidget(explanation);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(refresh, &QPushButton::clicked, this, [this] { if (session) session->refresh(); });
    connect(input, &NetworkPolicySession::changed, this, &NetworkPolicyWindow::updateModel);
    connect(input, &QObject::destroyed, this, [this] { updateModel(); reject(); });
    updateModel();
}

void NetworkPolicyWindow::updateModel()
{
    targets->clear();
    refresh->setEnabled(false);
    if (!session) { status->setText(QStringLiteral("连接已结束。")); return; }
    using Status = CoreEngine::RequestStatus;
    const auto result = session->status();
    if (result == Status::Stale) { status->setText(QStringLiteral("连接已结束。")); return; }
    if (result == Status::Unavailable) { status->setText(QStringLiteral("当前没有完整的网络检查结果。请先连接，或确认系统支持读取网络信息。")); return; }
    refresh->setEnabled(!session->isBusy());
    if (result == Status::Pending) { status->setText(QStringLiteral("正在读取原网络与校园资源…")); return; }
    if (result != Status::Success) { status->setText(QStringLiteral("网络信息读取失败，可以刷新重试。")); return; }
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
        new QTreeWidgetItem(targets, {scope["prefix"].toString(), origins.join('\n'), overlaps.join('\n')});
    }
    status->setText(QStringLiteral("检测到 %1 个原网络范围、%2 项校园地址重叠。").arg(scopes.size()).arg(conflicts.size()));
}
