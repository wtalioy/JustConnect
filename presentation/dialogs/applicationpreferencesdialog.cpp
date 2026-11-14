#include "applicationpreferencesdialog.h"
#include "presentation/widgets/applicationpreferenceswidget.h"

#include <QDialogButtonBox>
#include <QEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QTimer>
#include <QVBoxLayout>

ApplicationPreferencesDialog::ApplicationPreferencesDialog(QWidget *parent) : QDialog(parent)
{
    setObjectName("applicationSettingsDialog");
    setWindowTitle(tr("App settings"));
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowModality(Qt::WindowModal);
    constexpr int padding=24,scrollInset=8;
    auto *layout=new QVBoxLayout(this);
    layout->setContentsMargins(padding,padding,scrollInset,padding);
    layout->setSpacing(16);
    auto *scroll=new QScrollArea(this);
    scroll->setObjectName("applicationSettingsScroll");
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    layout->addWidget(scroll);
    auto *contents=new ApplicationPreferencesWidget(scroll);
    contents->layout()->setContentsMargins(0,0,padding-scrollInset,0);
    connect(contents,&ApplicationPreferencesWidget::startupSaveStarted,this,[this] {
        setAttribute(Qt::WA_DeleteOnClose,false);
    });
    connect(contents,&ApplicationPreferencesWidget::startupSaveFinished,this,[this] {
        setAttribute(Qt::WA_DeleteOnClose);
        if (!isVisible()) deleteLater();
    });
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Close,this);
    buttons->setObjectName("applicationSettingsButtons");
    buttons->setContentsMargins(0,0,padding-scrollInset,0);
    connect(buttons,&QDialogButtonBox::rejected,this,&QDialog::reject);
    layout->addWidget(buttons);
    setMinimumSize(320,360);
    resize(560,560);
    scroll->setWidget(contents);
    ensurePolished();
    layout->activate();
    contents->layout()->activate();
    scroll->setFocus(Qt::OtherFocusReason);
    scroll->verticalScrollBar()->setValue(0);
    // Let the first show size the viewport before enabling the scrollbar.
    QTimer::singleShot(0,scroll,[scroll] { scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded); });
}

void ApplicationPreferencesDialog::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type()==QEvent::LanguageChange) setWindowTitle(tr("App settings"));
}
