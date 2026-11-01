#include <QCoreApplication>
#include <QImage>
#include <QPainter>
#include <QSvgRenderer>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 3) return 1;
    QSvgRenderer svg(QString::fromLocal8Bit(argv[1]));
    if (!svg.isValid()) return 1;
    // AppImage requires a raster directory icon; keep the SVG as the only source.
    QImage image(256, 256, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    svg.render(&painter);
    painter.end();
    return image.save(QString::fromLocal8Bit(argv[2]), "PNG") ? 0 : 1;
}
