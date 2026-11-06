#pragma once
#include <QWidget>
class QComboBox;
class QCheckBox;
class QLabel;
class QPushButton;

class ApplicationPreferencesWidget final : public QWidget {
    Q_OBJECT
public:
    explicit ApplicationPreferencesWidget(QWidget *parent);
protected:
    void changeEvent(QEvent *event) override;
private:
    void retranslate();
    void savePreferences();
    QComboBox *language,*behavior;
    QCheckBox *autoStart,*silentStart;
    QLabel *languageLabel,*behaviorLabel,*hint,*error;
    QPushButton *controller;
    const char *errorText=nullptr;
};
