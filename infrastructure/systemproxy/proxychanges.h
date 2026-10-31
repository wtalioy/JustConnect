#pragma once
#include <QObject>
#include <memory>

class ProxyChanges final : public QObject
{
    Q_OBJECT
public:
    explicit ProxyChanges(QObject *parent = nullptr);
    ~ProxyChanges() override;
signals:
    void changed();
private:
    struct Watch;
    std::unique_ptr<Watch> watch;
};
