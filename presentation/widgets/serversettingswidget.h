#pragma once
#include <QWidget>
#include <QMap>
#include <QVariantMap>
class QComboBox;
class QFormLayout;
class QLabel;
class QCheckBox;
class QPlainTextEdit;
class QLineEdit;
class QSettings;
class QSpinBox;

class ServerSettingsWidget : public QWidget {
    Q_OBJECT
public:
    explicit ServerSettingsWidget(QWidget *parent = nullptr);
    void load(const QSettings &settings);
    QVariantMap settingsValues() const;
    QString serverAddress() const;
    int serverPort() const;
    bool prefersOAuth() const;
signals:
    void serverChanged();
protected:
    void changeEvent(QEvent *event) override;
private:
    void retranslate();
    void updateSecuritySummary();
    void selectPreset();
    QFormLayout *form, *advancedForm;
    QLabel *warning, *nodeWarning, *rulesHelp, *securitySummary, *domainDnsLabel;
    QComboBox *preset;
    QLineEdit *address;
    QSpinBox *port;
    QCheckBox *verify;
    QCheckBox *allowUnverifiedNodes;
    QPlainTextEdit *caPem;
    QPlainTextEdit *domainDnsRules;
    QString previousPreset, customAddress;
    QMap<QString,QString> domainDnsDrafts;
    int customPort = 443;
};
