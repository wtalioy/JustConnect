#pragma once

#include <QDialog>

class ApplicationPreferencesDialog final : public QDialog {
    Q_OBJECT
public:
    explicit ApplicationPreferencesDialog(QWidget *parent);
protected:
    void changeEvent(QEvent *event) override;
};
