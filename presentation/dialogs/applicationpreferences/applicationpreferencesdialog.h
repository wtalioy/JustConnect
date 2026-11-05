#pragma once
#include <QDialog>

class QComboBox;
class QLabel;
class QPushButton;

class ApplicationPreferencesDialog final : public QDialog {
    Q_OBJECT
public:
    explicit ApplicationPreferencesDialog(QWidget *parent);
protected:
    void changeEvent(QEvent *event) override;
private:
    void retranslate();
    QComboBox *language,*behavior;
    QLabel *languageLabel,*behaviorLabel,*hint,*error;
    QPushButton *controller;
};
