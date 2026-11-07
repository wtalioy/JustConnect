#include "presentation/appearance/applicationappearance.h"
#include "presentation/widgets/profilemenubutton.h"
#include "tests/uiwait.h"
#include <QApplication>
#include <QBackingStore>
#include <QDialog>
#include <QMainWindow>
#include <QPushButton>
#include <QToolButton>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QImage>
#include <QLabel>
#include <QWindow>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QAbstractButton>
#include <QStyleOption>
#include <QStyle>
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
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    ApplicationAppearance::install();
    QMainWindow dialog;
    ApplicationAppearance::install(&dialog);
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
            "main content stays opaque while the header alone can reveal a native material");
        if (dialog.property("nativeBackdrop").toBool()) {
            const int alpha=clean.pixelColor(clean.width()/2,clean.height()/2).alpha();
            if (!clean.hasAlphaChannel() || alpha==255)
                std::cerr<<"backdrop format="<<int(clean.format())<<" content alpha="<<alpha
                    <<" requested alpha="<<dialog.windowHandle()->requestedFormat().alphaBufferSize()
                    <<" translucent="<<dialog.testAttribute(Qt::WA_TranslucentBackground)<<'\n';
            check(clean.hasAlphaChannel() && alpha<255,"the painted content retains transparency for the system backdrop");
            check(dialog.testAttribute(Qt::WA_TranslucentBackground),"native glass retains transparent painting");
        }
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
    QComboBox choice;choice.addItem("School");layout.addWidget(&choice);
    QSpinBox port;port.setRange(1,65535);port.setValue(443);layout.addWidget(&port);
    inputs.resize(360,160);inputs.show();QCoreApplication::processEvents();
    check(!inputs.property("nativeBackdrop").toBool() && !inputs.testAttribute(Qt::WA_TranslucentBackground)
        && inputs.grab().toImage().pixelColor(2,2).alpha()==255,
        "ordinary dialogs never inherit the main window's backdrop or translucency");
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
    ProfileMenuButton school;school.setObjectName("profileMenuButton");school.setText("MMM");
    layout.addWidget(&school);school.show();QCoreApplication::processEvents();
    const auto shortWidth=school.width();
    const auto frame=school.grab().toImage();const auto ratio=frame.devicePixelRatio();
    const auto inkColumn=[&](int x) {
        for(int y=4*ratio;y<frame.height()-4*ratio;++y) {
            const auto color=frame.pixelColor(x,y);
            if(color.alpha()>100 && qMax(color.red(),qMax(color.green(),color.blue()))<180) return true;
        }
        return false;
    };
    int x=frame.width()-1;
    while(x>=0 && !inkColumn(x)) --x;
    check(x>=0,"the school selector paints its chevron");
    while(x>=0 && inkColumn(x)) --x;
    const int arrowStart=x+1;
    while(x>=0 && !inkColumn(x)) --x;
    const auto gap=(arrowStart-x-1)/ratio;
    check(x>=0 && gap>=8 && gap<=16,"the school caption and chevron have a visible, balanced gap at every scale");
    school.setText("A longer school");QCoreApplication::processEvents();
    check(school.width()>shortWidth,"the selector grows naturally with its caption");
    const auto windowWidth=inputs.width();const QString longName(100,'W');
    school.setText(longName);QCoreApplication::processEvents();
    check(inputs.width()==windowWidth && school.text()==longName,
        "long school captions fit the window while retaining their full accessible text");
    layout.removeWidget(&school);school.setText("Default");
    auto fractionalFont=school.font();fractionalFont.setLetterSpacing(QFont::AbsoluteSpacing,0.2);school.setFont(fractionalFont);
    school.resize(school.sizeHint());const auto caption=school.grab().toImage();
    const int captionWidth=school.width()-40;school.resize(school.width()+20,school.height());
    const auto roomy=school.grab().toImage();const auto scale=caption.devicePixelRatio();
    check(caption.copy(10*scale,4*scale,captionWidth*scale,(school.height()-8)*scale)
        ==roomy.copy(20*scale,4*scale,captionWidth*scale,(school.height()-8)*scale),
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
    std::cout<<"PASS: transparent repaint, dialog reopening, and input action alignment\n";
}
