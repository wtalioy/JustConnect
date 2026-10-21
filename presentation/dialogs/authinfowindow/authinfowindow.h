#pragma once

#include "ui_authinfowindow.h"
#include <QDialog>
#include <QJsonObject>
#include "core/connectionprofile.h"

class CoreEngine;
class AuthMethodsQuery;

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

private:
	Ui::AuthInfoWindow *ui;
    AuthMethodsQuery *query;
    bool preferOAuth = false;
    bool queryCompleted = false;
};
