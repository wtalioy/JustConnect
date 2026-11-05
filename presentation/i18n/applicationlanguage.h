#pragma once
#include <QObject>
#include <QTranslator>
#include <memory>

class ApplicationLanguage final : public QObject {
    Q_OBJECT
public:
    static ApplicationLanguage &instance();
    QString current() const { return language; }
    bool savePreferences(const QString &language,bool closeToTray);
private:
    explicit ApplicationLanguage(QObject *parent);
    bool activate(const QString &language,bool save,bool closeToTray);
    QString language;
    std::unique_ptr<QTranslator> application;
};
