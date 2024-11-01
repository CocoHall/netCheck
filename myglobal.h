#ifndef MYGLOBAL_H
#define MYGLOBAL_H

#include <QString>
#include "mywireshark.h"
#include <QList>
#include <QMutex>
#include <QPair>
#define PINGCOUNT 5
#define PINGTIMEOUT 3

class myglobal
{
public:
    myglobal();
    static int pingActive;
    static bool enable_A;
    static bool enable_B;
    static bool enable_C;
    static QString ip_A;
    static QString ip_B;
    static QString ip_C;
    static QString startTime;

    static QString info_save_dir;
    static QString info_zip_save_dir;
    static QString log_save_dir;
    static QString wireshark_save_dir;
    static QString process_save_dir;

    static QString project_900_sisPrj;

    static QList<mywireshark*> mywiresharkclasslist;
//    static QList<QPair<QString,QMutex*>*> mywiresharkMutexList;

};

#endif // MYGLOBAL_H
