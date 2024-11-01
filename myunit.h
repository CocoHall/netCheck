#ifndef MYUNIT_H
#define MYUNIT_H

#include <QObject>
#include <QDir>
class myunit
{
public:
    myunit();
    static void mkdir(QString path);
    static bool copyDir(const QString &source, const QString &destination,int filter);
};

#endif // MYUNIT_H
