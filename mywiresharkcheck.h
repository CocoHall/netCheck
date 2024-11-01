#ifndef MYWIRESHARKCHECK_H
#define MYWIRESHARKCHECK_H

#include <QObject>
#include <QThread>
#include <QList>
#include "myglobal.h"
#include "mywireshark.h"

class mywiresharkCheck:public QThread
{
    Q_OBJECT
public:
    mywiresharkCheck();
    void run();
    int active=0;

//    QList<mywireshark*>* mywiresharkclasslist_p;
public:
signals:
    void signal_lossRate(QString sip_type,long shouldReceived,long hasReceived);
    void signal_netchart(QString);
};

#endif // MYWIRESHARKCHECK_H
