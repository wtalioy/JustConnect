#pragma once
#include <QWidget>
#include <QFutureWatcher>
#include <optional>
#include "application/platformoperationresult.h"
class QComboBox;
class QCheckBox;
class QLabel;
class QPushButton;
class QGroupBox;

class ApplicationPreferencesWidget final : public QWidget {
    Q_OBJECT
public:
    explicit ApplicationPreferencesWidget(QWidget *parent);
    bool isSavingStartup() const { return pendingAutoStart.has_value(); }
signals:
    void startupSaveStarted();
    void startupSaveFinished();
protected:
    void changeEvent(QEvent *event) override;
private:
    void retranslate();
    void savePreferences();
    QComboBox *language,*behavior;
    QCheckBox *autoStart,*silentStart;
    QLabel *languageLabel,*behaviorLabel,*hint,*error;
    QPushButton *controller;
    QGroupBox *behaviorGroup,*startupGroup,*clashGroup;
    const char *errorText=nullptr;
    PlatformOperationResult operationError;
    std::optional<bool> pendingAutoStart;
    QFutureWatcher<PlatformOperationResult> startupOperation;
};
