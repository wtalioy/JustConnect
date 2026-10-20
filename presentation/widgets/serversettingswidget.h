#pragma once
#include <QWidget>
class QComboBox;
class QLineEdit;
class QSettings;
class QSpinBox;

class ServerSettingsWidget : public QWidget {
    Q_OBJECT
public:
    explicit ServerSettingsWidget(QWidget *parent = nullptr);
    void load(const QSettings &settings);
    void applyTo(QSettings &settings) const;
    QString serverAddress() const;
    int serverPort() const;
    bool isFudan() const;
signals:
    void serverChanged();
private:
    void selectPreset();
    QComboBox *preset;
    QLineEdit *address;
    QSpinBox *port;
    QString previousPreset, customAddress;
    int customPort = 443;
};
