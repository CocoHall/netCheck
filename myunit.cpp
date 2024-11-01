#include "myunit.h"

myunit::myunit()
{

}

void myunit::mkdir(QString path){
    QDir dir;
    dir.mkpath(path);
}

//filter1：log和ini文件
bool myunit::copyDir(const QString &source, const QString &destination,int filter)
{
    QDir directory(source);
    if(directory.dirName()=="TRENDRECORD"){//历史趋势
        return false;
    }

    if (!directory.exists())
    {
        return false;
    }

    QString srcPath = QDir::toNativeSeparators(source);
    if (!srcPath.endsWith(QDir::separator()))
        srcPath += QDir::separator();
    QString dstPath = QDir::toNativeSeparators(destination);
    if (!dstPath.endsWith(QDir::separator()))
        dstPath += QDir::separator();                                   //目录后面统一加上 /

    bool error = false;
    QStringList fileNames = directory.entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden);

    for (QStringList::size_type i=0; i != fileNames.size(); ++i)
    {
        QString fileName = fileNames.at(i);
        QString srcFilePath = srcPath + fileName;
        QString dstFilePath = dstPath + fileName;
        QFileInfo fileInfo(srcFilePath);

        if (fileInfo.isFile() || fileInfo.isSymLink())
        {
            if(filter==1){
                QString fileSuffix = fileInfo.suffix();
                if(fileSuffix.toUpper()!="LOG" && fileSuffix.toUpper()!="INI")continue;
            }
            QFile::setPermissions(dstFilePath, QFile::WriteOwner);
            QFile::copy(srcFilePath, dstFilePath);
        }
        else if (fileInfo.isDir())
        {
            QDir dstDir(dstFilePath);
            dstDir.mkpath(dstFilePath);
            if (!copyDir(srcFilePath, dstFilePath,filter))
            {
                error = true;
            }
        }
    }

    return !error;
}
