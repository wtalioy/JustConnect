#include "applicationlanguage.h"
#include "infrastructure/settings/profilemanager.h"
#include <QApplication>
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
    if (next=="zh_CN") {
        if (!translated->load(":/i18n/justconnect_zh_CN.qm")) return false;
    }
    if (save && !ProfileManager().setApplicationPreferences(next,closeToTray)) return false;
    language=next;
    QLocale::setDefault(QLocale(next));
    if (application) qApp->removeTranslator(application.get());
    application=std::move(translated);
    if (!application->isEmpty()) qApp->installTranslator(application.get());
    return true;
}
