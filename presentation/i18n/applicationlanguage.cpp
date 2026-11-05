#include "applicationlanguage.h"
#include "infrastructure/settings/profilemanager.h"
#include <QApplication>
#include <QLibraryInfo>
#include <QLocale>

ApplicationLanguage &ApplicationLanguage::instance() {
    auto *language=qApp->findChild<ApplicationLanguage *>(QString(),Qt::FindDirectChildrenOnly);
    if (!language) language=new ApplicationLanguage(qApp);
    return *language;
}
ApplicationLanguage::ApplicationLanguage(QObject *parent) : QObject(parent) {
    const auto requested=ProfileManager().language();
    if (!activate(ProfileManager::supportsLanguage(requested)?requested:QString("en"),false,true)) activate("en",false,true);
}
bool ApplicationLanguage::savePreferences(const QString &language,bool closeToTray) {
    return activate(language,true,closeToTray);
}
bool ApplicationLanguage::activate(const QString &next,bool save,bool closeToTray) {
    if (!ProfileManager::supportsLanguage(next)) return false;
    if (next==language) return !save || ProfileManager().setApplicationPreferences(next,closeToTray);
    auto translated=std::make_unique<QTranslator>();
    auto qt=std::make_unique<QTranslator>();
    if (next=="zh_CN") {
        if (!translated->load(":/i18n/justconnect_zh_CN.qm")) return false;
        qt->load(QLocale(next),"qtbase","_",QLibraryInfo::path(QLibraryInfo::TranslationsPath));
    }
    if (save && !ProfileManager().setApplicationPreferences(next,closeToTray)) return false;
    language=next;
    QLocale::setDefault(QLocale(next));
    if (application) qApp->removeTranslator(application.get());
    if (standard) qApp->removeTranslator(standard.get());
    application=std::move(translated);standard=std::move(qt);
    if (!standard->isEmpty()) qApp->installTranslator(standard.get());
    if (!application->isEmpty()) qApp->installTranslator(application.get());
    return true;
}
