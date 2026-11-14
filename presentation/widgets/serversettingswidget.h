#pragma once
#include <QWidget>
#include <QVariantMap>
class QFormLayout;
class QLabel;
class QCheckBox;
class QComboBox;
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
    bool isBuiltIn() const;
signals:
    void serverChanged();
protected:
    void changeEvent(QEvent *event) override;
private:
    void retranslate();
    void updateRoutingFields();
    QFormLayout *form;
    QLabel *warning, *nodeWarning, *rulesHelp, *domainDnsLabel, *caLabel, *clashHelp, *clashTargetsLabel;
    QLineEdit *address;
    QSpinBox *port, *socksPort;
    QComboBox *routingMode;
    QCheckBox *verify;
    QCheckBox *allowUnverifiedNodes;
    QPlainTextEdit *caPem;
    QPlainTextEdit *domainDnsRules;
    QPlainTextEdit *clashTargets;
    bool builtIn = false;
};
