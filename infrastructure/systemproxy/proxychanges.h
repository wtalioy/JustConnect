#pragma once
#include <QObject>
#include <QTimer>
#include <functional>
#include <memory>

class ProxyChanges final : public QObject
{
    Q_OBJECT
public:
    explicit ProxyChanges(QObject *parent = nullptr);
    ~ProxyChanges() override;
#ifdef Q_OS_LINUX
    // Linux-only test seams: the CI image has no dconf session, so tests inject
    // a snapshot reader and drive notifications directly.
    void setSnapshotReader(std::function<QByteArray()> reader);
    // One GSettings notification. Batches the signal with the others of a
    // write burst into a single snapshot read.
    void noteSignal();
    void handleSignal();
#endif
signals:
    void changed();
private:
    struct Watch;
    std::unique_ptr<Watch> watch;
#ifdef Q_OS_LINUX
    QTimer batch;
#endif
};
