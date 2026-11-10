#include "presentation/appearance/applicationappearance.h"
#include "presentation/presentationhelpers.h"
#include "presentation/widgets/profilemenubutton.h"
#include "tests/uiwait.h"
#include <QApplication>
#include <QBackingStore>
#include <QDialog>
#include <QDir>
#include <QMainWindow>
#include <QPushButton>
#include <QToolButton>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QImage>
#include <QPainter>
#include <QLabel>
#include <QWindow>
#include <QLineEdit>
#include <QComboBox>
#include "presentation/widgets/alignedcheckbox.h"
#include <QAbstractItemView>
#include <QStandardItemModel>
#include <QSpinBox>
#include <QAbstractButton>
#include <QStyleOption>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>
#include <cstdlib>
#include <iostream>

static void check(bool ok,const char *message) {
    if (!ok) {std::cerr<<message<<'\n';std::exit(1);}
}
class ObservedLabel final : public QLabel {
public:
    using QLabel::QLabel;
    QImage frame;
    int paints=0;
protected:
    void paintEvent(QPaintEvent *event) override {
        QLabel::paintEvent(event);
        auto *root=window();
        check(root->backingStore() && root->backingStore()->paintDevice(),"visible dialog has a raster backing store");
        auto *device=root->backingStore()->paintDevice();
        check(device->devType()==QInternal::Image,"observe raster pixels during the real paint operation");
        const auto ratio=root->devicePixelRatioF();
        const QRect area(mapTo(root,QPoint(0,0))*ratio,size()*ratio);
        // Cocoa can rotate/unlock IOSurface buffers after painting; copy only this valid region while it is locked.
        frame=static_cast<QImage *>(device)->copy(area);
        ++paints;
    }
};
static void actionPromptLayout(QWidget &parent,QDialogButtonBox::StandardButton primary,
    QDialogButtonBox::StandardButton dismiss,const QString &title,const QString &body,
    const QString &label,const QString &reportName)
{
    bool observed=false;
    QTimer::singleShot(0,&parent,[&] {
        auto *dialog=qobject_cast<QDialog *>(QApplication::activeModalWidget());
        check(dialog && dialog->objectName()=="actionPrompt","the styled prompt is the active modal dialog");
        auto *box=dialog->findChild<QDialogButtonBox *>();
        auto *icon=dialog->findChild<QLabel *>("promptIcon");
        auto *text=dialog->findChild<QLabel *>("promptBody");
        auto *action=box->button(primary);
        auto *cancel=box->button(dismiss);
        check(dialog->windowTitle()==title && text->text()==body
            && dialog->findChildren<QLabel *>().size()==2,
            "the native title is the only heading and the body appears once");
        check(icon->size()==QSize(36,36) && qAbs(icon->geometry().center().y()-text->geometry().center().y())<=1,
            "prompt icon is aligned with the body");
        check(text->height()>=text->heightForWidth(text->width()) && dialog->rect().contains(box->geometry())
            && action->height()==cancel->height() && box->rect().contains(action->geometry()),
            "wrapped copy and both actions fit inside the prompt");
        check(text->height()<=qMax(icon->height(),text->heightForWidth(text->width()))+2,
            "the dialog leaves no extra vertical space around the wrapped copy");
        for (auto *button : {action,cancel}) {
            QStyleOptionButton option;
            option.initFrom(button);
            option.text=button->text();
            const auto contents=button->style()->subElementRect(QStyle::SE_PushButtonContents,&option,button);
            check(contents.width()>=button->fontMetrics().size(Qt::TextShowMnemonic,button->text()).width(),
                "button text fits with the shared padding");
        }
        check(action->property("promptPrimary").toBool() && cancel->isDefault() && !action->isDefault(),
            "the blue action and safe keyboard default are independent");
        const auto fill = [](QPushButton *button) {
            const auto pixels = button->grab().toImage();
            return pixels.pixelColor(pixels.width()/2,qRound(8*button->devicePixelRatioF()));
        };
        const auto actionFill=fill(action), cancelFill=fill(cancel);
        check(actionFill.blue()>actionFill.red()+60 && actionFill.green()<170
            && cancelFill.red()>220 && cancelFill.green()>220,
            "the affirmative button renders blue and the keyboard default renders neutral");
        const auto report=qEnvironmentVariable("JC_UI_REPORT_DIR");
        if (!report.isEmpty()) check(dialog->grab().save(QDir(report).filePath(reportName)),"save styled prompt screenshot");
        observed=true;
        if (primary==QDialogButtonBox::Yes) {
            QKeyEvent enter(QEvent::KeyPress,Qt::Key_Return,Qt::NoModifier);
            QCoreApplication::sendEvent(dialog,&enter);
        } else {
            action->click();
        }
    });
    const bool accepted=PresentationHelpers::actionPrompt(&parent,title,body,primary,dismiss,label);
    check(observed && accepted==(primary!=QDialogButtonBox::Yes),"Return dismisses a deletion and the settings button accepts");
}

static void checkboxAlignment(const QString &caption) {
    AlignedCheckBox checkbox(caption);
    checkbox.resize(240, 36);
    checkbox.ensurePolished();
    QStyleOptionButton checkboxOption;
    checkboxOption.initFrom(&checkbox);
    checkboxOption.text = checkbox.text();
    const auto indicator = checkbox.style()->subElementRect(QStyle::SE_CheckBoxIndicator, &checkboxOption, &checkbox);
    const auto checkboxCaption = checkbox.style()->subElementRect(QStyle::SE_CheckBoxContents, &checkboxOption, &checkbox);
    check(!indicator.isEmpty() && checkbox.rect().contains(indicator) && !checkboxCaption.isEmpty()
        && qAbs(indicator.center().y()-checkboxCaption.center().y())<=1,
        "the indicator and caption share the vertical center of the checkbox");
    checkbox.setChecked(true);
    const auto mark = checkbox.grab();
    const auto pixels = mark.toImage();
    QRect squarePixels;
    QRect captionPixels;
    qint64 captionRowSum = 0;
    int captionInk = 0;
    for (int y = 0; y < pixels.height(); ++y) {
        for (int x = 0; x < pixels.width(); ++x) {
            const auto color = pixels.pixelColor(x, y);
            if (x < checkboxCaption.left() * mark.devicePixelRatio() && color == QColor("#5362df"))
                squarePixels = squarePixels.united(QRect(x, y, 1, 1));
            // Subpixel text can be dark even when one color channel stays bright.
            if (x >= checkboxCaption.left() * mark.devicePixelRatio() && qGray(color.rgb()) < 115) {
                captionPixels = captionPixels.united(QRect(x, y, 1, 1));
                captionRowSum += y;
                ++captionInk;
            }
        }
    }
    check(!squarePixels.isEmpty() && captionInk > 0, "the captured checkbox contains its square and caption");
    const auto captionCenter = double(captionRowSum) / captionInk;
    const auto squareCenter = (squarePixels.top() + squarePixels.bottom()) / 2.0;
    const auto captionBoundsCenter = (captionPixels.top() + captionPixels.bottom()) / 2.0;
    if (qAbs(squareCenter - captionBoundsCenter) > mark.devicePixelRatio()
        || qAbs(squareCenter - captionCenter) > 2 * mark.devicePixelRatio())
        std::cerr << caption.toStdString() << ": checkbox center " << squareCenter
                  << ", caption bounds center " << captionBoundsCenter << ", ink center " << captionCenter << '\n';
    check(qAbs(squareCenter - captionBoundsCenter) <= mark.devicePixelRatio(),
        "the checkbox and visible caption bounds align to within one logical pixel");
    check(qAbs(squareCenter - captionCenter) <= 2 * mark.devicePixelRatio(),
        "the painted checkbox square is vertically centered on its visible caption");
    bool checkMarkPainted = false;
    const auto insideSquare = squarePixels.adjusted(3, 3, -3, -3);
    for (int y = insideSquare.top(); y <= insideSquare.bottom(); ++y)
        for (int x = insideSquare.left(); x <= insideSquare.right(); ++x)
            checkMarkPainted |= pixels.pixelColor(x, y).lightness() > 220;
    check(checkMarkPainted, "the checked square paints its contrasting check mark");
}

int main(int argc,char **argv) {
    QApplication app(argc,argv);
    ApplicationAppearance::install();
    if (app.arguments().contains("--checkbox-only")) {
        checkboxAlignment(QStringLiteral("Remember authentication"));
        checkboxAlignment(QStringLiteral("Check for updates at startup"));
        checkboxAlignment(QStringLiteral("Start in the background"));
        checkboxAlignment(QStringLiteral("Skip tunnel verification"));
        checkboxAlignment(QStringLiteral("验证服务器证书"));
        checkboxAlignment(QStringLiteral("记住登录"));
        return 0;
    }
    QWidget promptParent;
    promptParent.show();
    actionPromptLayout(promptParent,QDialogButtonBox::Yes,QDialogButtonBox::No,"Clear authentication cache",
        "Clear the saved sign-in for account@example.edu on vpn.example.edu?\nYou may need to sign in again. Passwords, TOTP and other accounts are kept.",
        {},"cache-prompt.png");
    actionPromptLayout(promptParent,QDialogButtonBox::Open,QDialogButtonBox::Cancel,"Background access required",
        "Allow JustConnect under Login Items & Extensions, then connect again.",
        "Open System Settings","background-prompt.png");
    promptParent.hide();
    checkboxAlignment(QStringLiteral("Launch at sign-in"));
    QMainWindow dialog;
    QPushButton disconnect("Disconnect",&dialog);
    disconnect.setObjectName("connectButton");
    disconnect.setDefault(true);
    disconnect.setProperty("primaryAction",false);
    disconnect.resize(152,46);
    disconnect.ensurePolished();
    const auto renderDisconnect=[&](QStyle::State state) {
        QImage image(disconnect.size(),QImage::Format_RGB32);image.fill(QColor("#fafbfc"));
        QPainter painter(&image);
        QStyleOptionButton option;option.initFrom(&disconnect);
        option.state=state | QStyle::State_Active | QStyle::State_Enabled;
        option.features=QStyleOptionButton::DefaultButton;option.text=disconnect.text();
        disconnect.style()->drawControl(QStyle::CE_PushButton,&option,&painter,&disconnect);
        painter.end();
        return image;
    };
    const auto resting=renderDisconnect(QStyle::State_None);
    const auto hovered=renderDisconnect(QStyle::State_MouseOver);
    const auto pressed=renderDisconnect(QStyle::State_MouseOver | QStyle::State_Sunken);
    const QPoint fillSample(12,23);
    check(resting.pixelColor(fillSample).lightness()>hovered.pixelColor(fillSample).lightness()
        && hovered.pixelColor(fillSample)==QColor("#e4e7ec") && pressed.pixelColor(fillSample)==QColor("#dce0e6"),
        "Disconnect stays neutral with distinct hover and press fills, including when it is the default button");
    bool darkText=false;
    for (int x=32;x<120;++x) for (int y=10;y<36;++y)
        darkText|=hovered.pixelColor(x,y).lightness()<70;
    check(darkText,"Disconnect keeps dark, legible text on hover");
    disconnect.hide();
    QToolButton gear(&dialog);gear.setObjectName("preferencesButton");gear.setAutoRaise(true);
    gear.resize(40,40);gear.ensurePolished();
    const auto gearFill=[&](QStyle::State state) {
        QImage image(gear.size(),QImage::Format_RGB32);image.fill(QColor("#fafbfc"));
        QPainter painter(&image);
        QStyleOptionToolButton option;option.initFrom(&gear);
        option.state=state | QStyle::State_Active | QStyle::State_Enabled | QStyle::State_AutoRaise;
        option.subControls=QStyle::SC_ToolButton;
        gear.style()->drawComplexControl(QStyle::CC_ToolButton,&option,&painter,&gear);
        return image.pixelColor(20,20);
    };
    check(gearFill(QStyle::State_None)==QColor("#fafbfc") && gearFill(QStyle::State_HasFocus)==QColor("#fafbfc")
        && gearFill(QStyle::State_MouseOver)==QColor("#e4e7ec"),
        "settings only fills on hover or press, independent of keyboard focus");
    gear.hide();
    dialog.resize(420,240);
    QWidget body(&dialog);body.setObjectName("homeBody");body.setGeometry(0,100,420,140);
    ObservedLabel title(&dialog);
    title.setGeometry(24,8,370,70);
    ObservedLabel content(&body);content.setGeometry(24,16,370,70);
    for (int cycle=0;cycle<3;++cycle) {
        title.clear();const int beforeShow=title.paints;dialog.show();dialog.update();
        UiWait::until(__FILE__,__LINE__,[&]{return title.paints>beforeShow;});
        const auto clean=title.frame;
        check(!clean.isNull(),"capture the actual exposed content instead of repainting it with QWidget::grab");
        check(!content.frame.isNull() && content.frame.pixelColor(content.frame.width()/2,content.frame.height()/2).alpha()==255,
            "main content stays opaque");
        check(clean.pixelColor(clean.width()/2,clean.height()/2).alpha()==255
            && !dialog.testAttribute(Qt::WA_TranslucentBackground),
            "the exposed header is opaque at every scale");
        auto paint=[&](const QString &text) {
            const int previous=title.paints;title.setText(text);title.repaint();
            UiWait::until(__FILE__,__LINE__,[&]{return title.paints>previous;});
        };
        paint("MMMMMMMMMM");
        check(title.frame!=clean,"the observed frame contains the actual status text");
        paint({});
        check(title.frame==clean,"clearing a status label erases its old pixels, including on reopened dialogs");
        dialog.close();QCoreApplication::processEvents();
    }
    QDialog inputs;QVBoxLayout layout(&inputs);
    QLineEdit secret;secret.setEchoMode(QLineEdit::Password);secret.setText("sample");secret.setClearButtonEnabled(true);
    secret.addAction(QIcon(":/resource/eye.svg"),QLineEdit::TrailingPosition);layout.addWidget(&secret);
    QComboBox choice;choice.addItem("Server preset");layout.addWidget(&choice);
    QSpinBox port;port.setRange(1,65535);port.setValue(443);layout.addWidget(&port);
    QSpinBox fixedPort;fixedPort.setRange(1,65535);fixedPort.setValue(443);fixedPort.setReadOnly(true);layout.addWidget(&fixedPort);
    inputs.resize(360,160);inputs.show();QCoreApplication::processEvents();
    check(!inputs.testAttribute(Qt::WA_TranslucentBackground)
        && inputs.grab().toImage().pixelColor(2,2).alpha()==255,
        "ordinary dialogs retain an opaque surface");
    check(secret.height()==choice.height() && choice.height()==port.height(),
        "single-line input types share a consistent outer height");
    const auto actions=secret.findChildren<QAbstractButton *>(QString(),Qt::FindDirectChildrenOnly);
    check(actions.size()==2,"the alignment check covers both the eye and clear actions");
    for (auto *button:actions) {
        check(secret.rect().contains(button->geometry()),"line edit actions stay inside the input at the current scale");
        check(std::abs(button->geometry().center().y()-secret.rect().center().y())<=1,
            "eye and clear actions are vertically centered instead of inheriting full-size button minimums");
    }
    QStyleOptionComboBox combo;combo.initFrom(&choice);combo.rect=choice.rect();
    const auto arrow=choice.style()->subControlRect(QStyle::CC_ComboBox,&combo,QStyle::SC_ComboBoxArrow,&choice);
    check(choice.rect().contains(arrow) && std::abs(arrow.center().y()-choice.rect().center().y())<=1,
        "the dropdown action is centered and contained in its input");
    QStyleOptionSpinBox spin;spin.initFrom(&port);spin.rect=port.rect();
    const auto up=port.style()->subControlRect(QStyle::CC_SpinBox,&spin,QStyle::SC_SpinBoxUp,&port);
    const auto down=port.style()->subControlRect(QStyle::CC_SpinBox,&spin,QStyle::SC_SpinBoxDown,&port);
    check(port.rect().contains(up) && port.rect().contains(down) && up.width()==down.width()
        && up.x()==down.x() && std::abs(up.center().y()+down.center().y()-2*port.rect().center().y())<=1,
        "numeric controls share the same trailing alignment and balanced hit areas");
    secret.setEchoMode(QLineEdit::Normal);secret.setText("MMM");secret.setClearButtonEnabled(false);
    choice.setItemText(0,"MMM");port.setSpecialValueText("MMM");port.setValue(port.minimum());
    QCoreApplication::processEvents();
    const auto textStart=[](QWidget *field) {
        const auto frame=field->grab().toImage();const auto ratio=frame.devicePixelRatio();
        for (int x=1;x<50*ratio;++x) {
            for (int y=8*ratio;y<frame.height()-8*ratio;++y) {
                const auto color=frame.pixelColor(x,y);
                if (color.alpha()>100 && color.red()<70 && color.green()<80 && color.blue()<100)
                    return x/ratio;
            }
        }
        check(false,"the text-alignment check observes actual rendered glyphs");return -1.0;
    };
    const auto lineStart=textStart(&secret),comboStart=textStart(&choice),spinStart=textStart(&port);
    if (std::abs(lineStart-comboStart)>1 || std::abs(lineStart-spinStart)>1)
        std::cerr<<"text starts: line="<<lineStart<<" combo="<<comboStart<<" spin="<<spinStart<<'\n';
    check(std::abs(lineStart-comboStart)<=1 && std::abs(lineStart-spinStart)<=1,
        "line edits, dropdowns and numeric inputs align their text, not just their outer borders");
    fixedPort.setSpecialValueText("MMM");fixedPort.setValue(fixedPort.minimum());
    check(std::abs(lineStart-textStart(&fixedPort))<=1,
        "read-only numeric fields still paint their value at the shared text inset");
    const auto paintsArrows=[](QSpinBox &field) {
        const auto frame=field.grab().toImage();
        const auto ratio=frame.devicePixelRatio();
        for (int y=1;y<frame.height()-1;++y) {
            for (int x=frame.width()-32*ratio;x<frame.width()-1;++x) {
                const auto color=frame.pixelColor(x,y);
                if (color.red()<180 && color.green()<180 && color.blue()<180) return true;
            }
        }
        return false;
    };
    check(paintsArrows(port) && !paintsArrows(fixedPort),"step arrows are hidden only for the read-only field");
    fixedPort.hide();
    choice.addItem("Unavailable");choice.addItem("Another preset");
    qobject_cast<QStandardItemModel *>(choice.model())->item(1)->setEnabled(false);
    QApplication::setEffectEnabled(Qt::UI_General,true);
    QApplication::setEffectEnabled(Qt::UI_AnimateCombo,true);
    choice.showPopup();
    auto *options=choice.view();
    // The opening animation shows a temporary surface before exposing the actual list.
    UiWait::until(__FILE__,__LINE__,[&]{
        const auto *surface=options->window()->windowHandle();
        return options->isVisible() && surface && surface->isExposed();
    });
    auto *popupFrame = qobject_cast<QFrame *>(options->window());
    check(popupFrame && popupFrame->frameWidth() == 0
        && !choice.style()->styleHint(QStyle::SH_ComboBox_Popup, &combo, &choice),
        "only the styled option list provides a dropdown border");
    const auto comboBottom = choice.mapToGlobal(QPoint(0, choice.height()));
    check(popupFrame->geometry().topLeft() == comboBottom + QPoint(0, 4),
        "a dropdown with room opens four pixels below and aligns with the field");
    const auto popupPixels = popupFrame->grab().toImage();
    const int borderX = popupPixels.width() / 2;
    int borderRows = 0;
    while (borderRows < popupPixels.height() && popupPixels.pixelColor(borderX, borderRows) == QColor("#dde2e9"))
        ++borderRows;
    check(borderRows > 0 && borderRows <= qCeil(popupPixels.devicePixelRatio()),
        "the popup has one painted border at the top edge");
    const auto lastRow=options->visualRect(choice.model()->index(2,0));
    check(options->viewport()->rect().contains(lastRow),
        "the dropdown sizes its popup for padded rows without clipping the final option");
    const int textHeight=options->fontMetrics().height();
    check(lastRow.height()>=qMax(24,textHeight) && lastRow.height()<=qMax(26,textHeight+16),
        "the opened dropdown keeps full text height without adding excess padding to the native row");
    QKeyEvent next(QEvent::KeyPress,Qt::Key_Down,Qt::NoModifier);
    QKeyEvent selectOverride(QEvent::ShortcutOverride,Qt::Key_Return,Qt::NoModifier);
    QKeyEvent select(QEvent::KeyPress,Qt::Key_Return,Qt::NoModifier);
    QApplication::sendEvent(options,&next);
    check(options->currentIndex().row()==2 && choice.currentIndex()==0,
        "keyboard navigation skips disabled choices before committing a dropdown selection");
    // Qt commits popup Return in ShortcutOverride, before dispatching the key press.
    QApplication::sendEvent(options,&selectOverride);QApplication::sendEvent(options,&select);
    // Native menu styles briefly flash the chosen row before hiding the popup.
    UiWait::until(__FILE__,__LINE__,[&]{return choice.currentIndex()==2 && !options->isVisible();});
    check(choice.currentIndex()==2 && !options->isVisible(),
        "styled dropdowns retain keyboard selection and skip disabled choices");
    ProfileMenuButton preset;preset.setObjectName("profileMenuButton");preset.setText("MMM");
    layout.addWidget(&preset);preset.show();QCoreApplication::processEvents();
    check(preset.font().pointSize()>0,"menu tools supply the native style with a valid point size");
    const auto shortWidth=preset.width();
    const auto frame=preset.grab().toImage();const auto ratio=frame.devicePixelRatio();
    const auto inkColumn=[&](int x) {
        for(int y=4*ratio;y<frame.height()-4*ratio;++y) {
            const auto color=frame.pixelColor(x,y);
            if(color.alpha()>100 && qMax(color.red(),qMax(color.green(),color.blue()))<180) return true;
        }
        return false;
    };
    int x=frame.width()-1;
    while(x>=0 && !inkColumn(x)) --x;
    check(x>=0,"the preset selector paints its chevron");
    while(x>=0 && inkColumn(x)) --x;
    const int arrowStart=x+1;
    while(x>=0 && !inkColumn(x)) --x;
    const auto gap=(arrowStart-x-1)/ratio;
    check(x>=0 && gap>=8 && gap<=16,"the preset caption and chevron have a visible, balanced gap at every scale");
    preset.setText("A longer preset");QCoreApplication::processEvents();
    check(preset.width()>shortWidth,"the selector grows naturally with its caption");
    const auto windowWidth=inputs.width();const QString longName(100,'W');
    preset.setText(longName);QCoreApplication::processEvents();
    check(inputs.width()==windowWidth && preset.text()==longName,
        "long preset captions fit the window while retaining their full accessible text");
    layout.removeWidget(&preset);preset.setText("Default");
    auto fractionalFont=preset.font();fractionalFont.setLetterSpacing(QFont::AbsoluteSpacing,0.2);preset.setFont(fractionalFont);
    preset.resize(preset.sizeHint());const auto caption=preset.grab().toImage();
    const int captionWidth=qCeil(QFontMetricsF(preset.font()).horizontalAdvance(preset.text()));
    preset.resize(preset.width()+20,preset.height());
    const auto roomy=preset.grab().toImage();const auto scale=caption.devicePixelRatio();
    check(caption.copy(10*scale,4*scale,captionWidth*scale,(preset.height()-8)*scale)
        ==roomy.copy(20*scale,4*scale,captionWidth*scale,(preset.height()-8)*scale),
        "natural-width captions render fully, matching a roomier button even with fractional glyph advances");
    QPushButton details("Details");details.setObjectName("detailsButton");details.setFlat(true);layout.addWidget(&details);details.show();
    QToolButton tool;tool.setAutoRaise(true);tool.setFocusPolicy(Qt::StrongFocus);layout.addWidget(&tool);tool.show();
    QWidget::setTabOrder(&secret,&details);QCoreApplication::processEvents();secret.setFocus();
    UiWait::until(__FILE__,__LINE__,[&]{return secret.hasFocus();});
    check(details.focusPolicy()==Qt::TabFocus && tool.focusPolicy()==Qt::TabFocus,
        "flat and icon tools keep keyboard focus without mouse click focus");
    const auto point=details.rect().center();
    QMouseEvent press(QEvent::MouseButtonPress,point,details.mapToGlobal(point),Qt::LeftButton,Qt::LeftButton,Qt::NoModifier);
    QMouseEvent release(QEvent::MouseButtonRelease,point,details.mapToGlobal(point),Qt::LeftButton,Qt::NoButton,Qt::NoModifier);
    QApplication::sendEvent(&details,&press);QApplication::sendEvent(&details,&release);
    check(secret.hasFocus(),"clicking Details does not leave a persistent focus frame on the tool");
    QKeyEvent tab(QEvent::KeyPress,Qt::Key_Tab,Qt::NoModifier);QApplication::sendEvent(&secret,&tab);
    UiWait::until(__FILE__,__LINE__,[&]{return details.hasFocus();});
    std::cout<<"PASS: connection button feedback, opaque repaint, dialog reopening, and input alignment\n";
}
