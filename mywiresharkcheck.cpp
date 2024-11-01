#include "mywiresharkcheck.h"

mywiresharkCheck::mywiresharkCheck()
{

}


void mywiresharkCheck::run(){
    active=1;
    while(active){
        int flag=0;
        for(int i=0;active && i<myglobal::mywiresharkclasslist.length();i++){
            if(myglobal::mywiresharkclasslist[i]->getActive()==0)continue;
            flag=1;
            QMap<QString,QMap<QString,QStringList>>::iterator iter;

            for(iter=myglobal::mywiresharkclasslist[i]->udp1919.begin();active && iter!=myglobal::mywiresharkclasslist[i]->udp1919.end();++iter){

                QString ipsrc_type = iter.key();
                qint64 startTime = iter.value()["time"][0].toLongLong();

                qint64 currentTime = QDateTime::currentDateTime().toMSecsSinceEpoch();
                if(currentTime<startTime)continue;
                //应收(currentTime-startTime)/1000包，已收iter.value().length()包，丢包率1-iter.value().length()*1.0 / ((currentTime-startTime)/1000)

                emit signal_lossRate(ipsrc_type,(currentTime-startTime)/1000+1,iter.value()["time"].length());//丢包率
                emit signal_netchart(ipsrc_type);                                                             //图表
            }
        }
        Sleep(1000);
        active=flag;
    }
}








