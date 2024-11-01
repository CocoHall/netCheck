#ifndef MYRECOMMEND_H
#define MYRECOMMEND_H

#include <QObject>
#include <QThread>
#include <QProcess>
#include <QDebug>
#include <QFile>
#include "mydcom.h"
class myrecommend:public QThread
{
    Q_OBJECT
public:
    myrecommend();
private:
    void run();


public:
signals:
    void signal_recommend(QString value);
};

#endif // MYRECOMMEND_H
