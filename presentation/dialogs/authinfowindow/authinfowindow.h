#pragma once

namespace Ui { class AuthInfoWindow; }
#include <QDialog>
#include <QJsonObject>
#include "core/connectionprofile.h"

class CoreEngine;
class AuthMethodsQuery;
class ControllerSelectionCoordinator;

class AuthInfoWindow : public QDialog
{
	Q_OBJECT

public:
	AuthInfoWindow(QWidget *parent = nullptr, CoreEngine *engine = nullptr);

    ~AuthInfoWindow() override;

    void fetchAuthInfo(const ConnectionProfile &profile, bool preferOAuth = false);

signals:
	void finishAuthInfo(const QJsonObject &method);

protected:
    void done(int result) override;
    void changeEvent(QEvent *event) override;

private:
    void setStatus(const char *source);
    const char *statusText=nullptr;
	Ui::AuthInfoWindow *ui;
    AuthMethodsQuery *query;
    ControllerSelectionCoordinator *controllerSelection;
    quint64 lookup = 0;
    bool preferOAuth = false;
    bool queryCompleted = false;
};
