#include "presentation/appearance/applicationappearance.h"
#include "tests/uiwait.h"
#include <QApplication>
#include <QBackingStore>
#include <QDialog>
#include <QImage>
#include <QLabel>
#include <QWindow>
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
    QDialog dialog;
    dialog.resize(420,240);
    ObservedLabel title(&dialog);
    title.setGeometry(24,60,370,70);
    for (int cycle=0;cycle<3;++cycle) {
        title.clear();const int beforeShow=title.paints;dialog.show();dialog.update();
        UiWait::until(__FILE__,__LINE__,[&]{return title.paints>beforeShow;});
        const auto clean=title.frame;
        check(!clean.isNull(),"capture the actual exposed content instead of repainting it with QWidget::grab");
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
    std::cout<<"PASS: incremental transparent repaint and three native dialog opens\n";
}
