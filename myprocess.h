#ifndef MYPROCESS_H
#define MYPROCESS_H

#include <QObject>
#include <QThread>
#include <QMap>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <QDebug>
#include <Winternl.h>
#include <QDir>

class myprocess : public QThread
{
    Q_OBJECT
public:
    explicit myprocess(QObject *parent = nullptr);
    void run();
    int active=1;
    void save(QString path);

private:
    int saveFlag=0;
    QString filePath;

public:
signals:
    void signal_process(QList<QMap<QString,QString>> info);
    void signal_processSave(int type,QString finishInfo);
};

#endif // MYPROCESS_H
