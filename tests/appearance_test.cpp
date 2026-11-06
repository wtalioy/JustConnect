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
static QImage paintedFrame(QWidget &window) {
    check(window.backingStore() && window.backingStore()->paintDevice(),"visible dialog has a raster backing store");
    auto *device=window.backingStore()->paintDevice();
    check(device->devType()==QInternal::Image,"inspect the painted frame, without repainting it with QWidget::grab");
    return static_cast<QImage *>(device)->copy();
}
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    ApplicationAppearance::install();
    QDialog dialog;
    dialog.resize(420,240);
    QLabel title(&dialog);
    title.setGeometry(24,60,370,70);
    auto font=title.font();font.setPixelSize(32);title.setFont(font);
    const bool native=QGuiApplication::platformName()=="windows" || QGuiApplication::platformName()=="cocoa";
    for (int cycle=0;cycle<3;++cycle) {
        title.clear();dialog.show();
        UiWait::until(__FILE__,__LINE__,[&]{return dialog.backingStore() && dialog.isVisible();});
        dialog.repaint();
        const auto clean=paintedFrame(dialog);
        if (native) check(dialog.windowHandle()->format().hasAlpha(),"native alpha must be requested before the first window creation");
        if (dialog.property("nativeBackdrop").toBool()) check(dialog.testAttribute(Qt::WA_TranslucentBackground),"native glass retains transparent painting");
        title.setText("MMMMMMMMMM");title.repaint();
        title.clear();title.repaint();
        const auto updated=paintedFrame(dialog);
        check(updated==clean,"clearing a status label must erase its old pixels, including on reopened dialogs");
        dialog.close();QCoreApplication::processEvents();
    }
    std::cout<<"PASS: incremental transparent repaint and three native dialog opens\n";
}
