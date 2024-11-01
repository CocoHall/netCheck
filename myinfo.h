#ifndef MYINFO_H
#define MYINFO_H

#include <QObject>
#include <QThread>
#include <QStringList>
#include <QProcess>
#include <QDir>
#include <QDebug>
#include <QSettings>
#include <QMessageBox>
#include <QDomElement>
#include <QUdpSocket>
#include <windows.h>
#include "myglobal.h"
#include "JlCompress.h"
#include "myunit.h"
class myinfo:public QThread
{
    Q_OBJECT
public:
    myinfo();
    ~myinfo();
    void setList(QStringList* checklist);
    void setDirname(QString path,QString path2);
    void saveSecedit();

    QStringList* checklist;

public:
signals:
    void signal_gather(QString tag);

private:


    QString dirname="";
    QString zipDirname="";
    QString CfgRefPath="",CfgRootPath="",CfgSvrPath="",IntallDirectory="",RunRefPath="",RunRootPath;
    QString getDCSInfo(quint16 srcPort,QString dstIP ,quint16 dstPort,char SeqNum,char offerset,char datalength);
    void getICSinfo();
    void run();
    void saveARPTable();
    void saveRoute();
    void saveNetcard();
    void saveFirewall();
    void savePort();
    void saveTasklist();
    void saveDCOM();
    void saveService();
    void saveKB();
    void saveSoft();
    void saveEvent();
    void saveDNS();
    void saveSchtasks();
    void saveStartup();
    void saveShare();
    void savePower();
    void saveSysteminfo();
    void saveAccount();
    void saveGroup();
    void saveRDP();
    void saveRecent();
    void saveSession();
    void saveOther();
    void saveReg();
    void save700Project();
    void save900Project();
    void saveScadaProject();
    void saveICSVF();
    void save700TimeSync();
    void save900TimeSync();
    void saveICSDCS();
};

#endif // MYINFO_H
