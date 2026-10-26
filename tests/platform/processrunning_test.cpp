#include "infrastructure/process/running.h"
#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *stage){if(!value)throw std::runtime_error(stage);}
int main(int argc,char **argv) try
{
    QCoreApplication app(argc,argv);
    if(argc==2 && QByteArray(argv[1])=="--idle"){
        std::cout<<"ready\n"<<std::flush;
        QTimer::singleShot(15000,&app,&QCoreApplication::quit);return app.exec();
    }
    QTemporaryDir folder;check(folder.isValid(),"private process fixture directory");
    const auto name="jc"+QUuid::createUuid().toString(QUuid::Id128).left(11);
    auto path=folder.filePath(name);
#ifdef Q_OS_WIN
    path+=".exe";
#endif
    check(isProcessRunning(name)==std::optional<bool>(false),"private child is absent before launch");
    check(QFile::copy(QCoreApplication::applicationFilePath(),path),"copy the owned process fixture");
    QProcess child;child.start(path,{"--idle"});
    check(child.waitForStarted(5000) && child.waitForReadyRead(5000) && child.readAllStandardOutput().contains("ready"),"ordinary child starts");
    check(isProcessRunning(name)==std::optional<bool>(true),"native enumeration finds the actual image basename");
    check(child.state()==QProcess::Running,"read-only detection never terminates the process");
    child.kill();check(child.waitForFinished(5000),"stop only the owned child fixture");
    check(isProcessRunning(name)==std::optional<bool>(false),"terminated child is no longer running");
    std::cout<<"PASS: native process basename detection, live preservation and disappearance\n";return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
