#pragma once

#include "ui_authinfowindow.h"
#include <QDialog>

class CoreEngine;

class AuthInfoWindow : public QDialog
{
	Q_OBJECT

public:
	AuthInfoWindow(QWidget *parent = nullptr, CoreEngine *engine = nullptr);

    ~AuthInfoWindow() override;

    void fetchAuthInfo(const QString& serverAddress, int port, bool preferOAuth = false);

signals:
	void finishAuthInfo(const QString& authType, const QString& loginDomain, const QString& loginUrl);

private:
	Ui::AuthInfoWindow *ui;
    CoreEngine *engine;
    bool preferOAuth = false;
    bool queryCompleted = false;
};
