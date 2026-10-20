#pragma once
#include "application/credentialstore.h"
#include <QHash>
#include <functional>

// Injected application port; platform tests exercise the actual OS stores separately.
class MemoryCredentialStore final: public CredentialStore {
public:
    QHash<QString,QByteArray> values;
    std::function<void()> beforeRead;
    CredentialStatus failure=CredentialStatus::Success;
    CredentialResult read(const QString &key) override {
        if (beforeRead) beforeRead();
        if (failure!=CredentialStatus::Success) return {failure,{}};
        return values.contains(key) ? CredentialResult{CredentialStatus::Success,values.value(key)} : CredentialResult{CredentialStatus::NotFound,{}};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        if (failure!=CredentialStatus::Success) return {failure,{}};
        values.insert(key,value);return {CredentialStatus::Success,{}};
    }
    CredentialResult remove(const QString &key) override {
        if (failure!=CredentialStatus::Success) return {failure,{}};
        values.remove(key);return {CredentialStatus::Success,{}};
    }
};
