#pragma once
#include <QWidget>
#include <QVariantMap>
class QFormLayout;
class QLabel;
class QCheckBox;
class QPlainTextEdit;
class QLineEdit;
class QSettings;
class QSpinBox;
class QToolButton;

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
    QFormLayout *form;
    QLabel *warning, *nodeWarning, *rulesHelp, *domainDnsLabel, *caLabel;
    QToolButton *caToggle;
    QLineEdit *address;
    QSpinBox *port;
    QCheckBox *verify;
    QCheckBox *allowUnverifiedNodes;
    QPlainTextEdit *caPem;
    QPlainTextEdit *domainDnsRules;
    bool builtIn = false;
};
