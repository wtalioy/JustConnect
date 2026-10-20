#ifndef AUTHDIALOGCOORDINATOR_H
#define AUTHDIALOGCOORDINATOR_H

#include <QObject>
#include <QPointer>
#include <QJsonObject>
#include <QUrl>

class GraphCaptchaWindow;
class LoginWindow;
class QDialog;
class SsoLoginWebView;
class QWidget;

class AuthDialogCoordinator : public QObject
{
    Q_OBJECT

public:
    explicit AuthDialogCoordinator(
        QWidget *parentWidget,
        QObject *parent = nullptr
    );

    void requestLogin(const QString &username, const QString &password);
    void requestPhoneNumber(
        const QString &countryCode,
        const QString &phoneNumber
    );
    void requestAuthentication(const QJsonObject &request, const QUrl &callbackServer);
    void closeAuthentication();

signals:
    void loginSubmitted(const QString &username, const QString &password, bool saveDetails);
    void phoneNumberSubmitted(
        const QString &countryCode,
        const QString &phoneNumber,
        bool saveDetails
    );
    void responseSubmitted(const QJsonObject &response);

private:
    QWidget *parentWidget;
    QPointer<LoginWindow> loginWindow;
    QPointer<QDialog> phoneNumberDialog;
    QPointer<QDialog> challengeDialog;
};

#endif // AUTHDIALOGCOORDINATOR_H
