#ifndef MYPERFORMANCE_H
#define MYPERFORMANCE_H

#include<windows.h>
#include<sddl.h>
#include <lm.h>
#include <iphlpapi.h>
#include <pdh.h>
#include <stdio.h>
#include <QThread>
#include "myheader.h"
#include<QDebug>

class myperformance:public QThread
{
    Q_OBJECT
public:
    myperformance();
    int  getPhyNetCardNum();
    char*  getPhyNetCardNames();
    void setActive(int flag);

    int getActive();

public:
signals:
    void signal_performance(int i,double value);
    void signal_performance_updateMaxY();

private:
    struct stru{
        char AdapterName[1024];
        char Description[1024];
        int phy;
    }stru1[STRUCTSIZE];

    int performance_running;
    void run();
    int phyNetCardNum=0;
    char phyNetCardNames[STRUCTSIZE*MAX_PATH+STRUCTSIZE]={0};
    HQUERY query;
    HCOUNTER counter[4*STRUCTSIZE+OTHER_HCOUNTER];

    void judgePhy(unsigned char* NetCfgInstanceId,DWORD Characteristics);
    void enumNetcard();
    void  collectData();
    double  getPdhValue(int index);
    void  closePdh();
    int  initPdh();
    void  initPhy();
};

#endif // MYPERFORMANCE_H
