#include "mytotal.h"

mytotal::mytotal(mywireshark* mywiresharkclass)
{
    this->mywiresharkclass=mywiresharkclass;
}

void mytotal::run(){
    unsigned long lastPackets=0,lastBytes1s=0,lastBytes100ms=0,lastBytes1ms=0;
    lastPackets=mywiresharkclass->totalPackets;
    lastBytes1s=mywiresharkclass->totalBytes;
    lastBytes100ms=mywiresharkclass->totalBytes;
    lastBytes1ms=mywiresharkclass->totalBytes;

    unsigned int i=0;
    while(mywiresharkclass->getActive()){
        emit signal_total(mywiresharkclass->totalBytes-lastBytes100ms,3);
        lastBytes100ms=mywiresharkclass->totalBytes;
        if(i%10==0 || i<10){
            emit signal_total(mywiresharkclass->totalPackets-lastPackets,1);
            emit signal_total(mywiresharkclass->totalBytes-lastBytes1s,2);
            lastPackets=mywiresharkclass->totalPackets;
            lastBytes1s=mywiresharkclass->totalBytes;
        }
        Sleep(100);
        i+=1;
    }

    emit signal_total(mywiresharkclass->totalPackets-lastPackets,1);
    emit signal_total(mywiresharkclass->totalBytes-lastBytes1s,2);
    emit signal_total(mywiresharkclass->totalBytes-lastBytes100ms,3);
}
