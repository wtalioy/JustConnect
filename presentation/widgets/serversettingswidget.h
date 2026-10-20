#pragma once
#include <QWidget>
#include <QVariantMap>
#include "core/connectionprofile.h"
class QComboBox;
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
    bool isFudan() const;
    TlsOptions tlsOptions() const;
signals:
    void serverChanged();
private:
    void selectPreset();
    QComboBox *preset;
    QLineEdit *address;
    QSpinBox *port;
    QCheckBox *verify;
    QPlainTextEdit *caPem;
    QString previousPreset, customAddress;
    int customPort = 443;
};
