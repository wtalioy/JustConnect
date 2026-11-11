#include "ui_loginwindow.h"
#include "loginwindow.h"
#include "presentation/presentationhelpers.h"
#include <QEvent>
#include <QPushButton>
#include <QKeyEvent>

LoginWindow::LoginWindow(QWidget *parent) : QDialog(parent),ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Sign in"));
    PresentationHelpers::passwordVisibilityAction(ui->passwordLineEdit);
    const auto updateLogin=[this] {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(
            !ui->usernameLineEdit->text().isEmpty() && !ui->passwordLineEdit->text().isEmpty());
    };
    connect(ui->usernameLineEdit,&QLineEdit::textChanged,this,updateLogin);
    connect(ui->passwordLineEdit,&QLineEdit::textChanged,this,updateLogin);
    updateLogin();
    setWindowModality(Qt::WindowModal);
    setAttribute(Qt::WA_DeleteOnClose);
    connect(ui->buttonBox->button(QDialogButtonBox::Ok),&QPushButton::clicked,this,[this] {
        emit login(ui->usernameLineEdit->text(),ui->passwordLineEdit->text(),ui->saveLoginDetailCheckBox->isChecked());
        accept();
    });
}

LoginWindow::~LoginWindow() {delete ui;}

void LoginWindow::setDetail(const QString &username,const QString &password)
{
    ui->usernameLineEdit->setText(username);
    ui->passwordLineEdit->setText(password);
}

void LoginWindow::keyPressEvent(QKeyEvent *event)
{
    if (event->key()==Qt::Key_Enter || event->key()==Qt::Key_Return)
        ui->buttonBox->button(QDialogButtonBox::Ok)->click();
    else if (event->key()==Qt::Key_Escape)
        reject();
    else
        QDialog::keyPressEvent(event);
}

void LoginWindow::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) {
        ui->retranslateUi(this);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Sign in"));
        PresentationHelpers::passwordVisibilityAction(ui->passwordLineEdit);
    }
}
