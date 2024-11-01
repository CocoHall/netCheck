#ifndef MYTOTAL_H
#define MYTOTAL_H

#include <QObject>
#include <QThread>
#include "mywireshark.h"
class mytotal:public QThread
{
    Q_OBJECT
public:
    mytotal(mywireshark* mywiresharkclass);

public: signals:
    void signal_total(unsigned long,unsigned long);

private:
    mywireshark* mywiresharkclass;
    void run();
};

#endif // MYTOTAL_H
