#include "myrecommend.h"

myrecommend::myrecommend()
{

}

void myrecommend::run()
{
    mydcom class_mydcom;

    emit signal_recommend("正在设置DCOM");
    QString currentSID = class_mydcom.getSIDByUsername(class_mydcom.getUserName());
    QString AccessRestriction=QString()+"O:BAG:BAD:(A;;CCDCLC;;;WD)(A;;CCDC;;;S-1-15-2-1)(A;;CCDC;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)(A;;CCDCLC;;;S-1-5-32-559)(A;;CCDCLC;;;S-1-5-32-562)(A;;CCDCLC;;;S-1-5-7)"+"(A;;CCDCLC;;;" + currentSID + ")";
    QString LaunchRestriction=QString()+"O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;S-1-5-32-559)(A;;CCDCSW;;;S-1-15-2-1)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)"+"(A;;CCDCLCSWRP;;;" + currentSID + ")";
    QString DefaultAccess=QString()+"O:BAG:BAD:(A;;CCDC;;;BA)(A;;CCDCLC;;;S-1-5-32-562)(A;;CCDC;;;SY)(A;;CCDC;;;PS)"+"(A;;CCDCLC;;;" + currentSID + ")";
    QString DefaultLaunch=QString()+"O:BAG:BAD:(A;;CCDCSW;;;BA)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCSW;;;IU)(A;;CCDCLCSWRP;;;SY)"+"(A;;CCDCLCSWRP;;;" + currentSID + ")";
    class_mydcom.setMachineAccessRestriction(AccessRestriction.toStdString().c_str());
    class_mydcom.setMachineLaunchRestriction(LaunchRestriction.toStdString().c_str());
    class_mydcom.setDefaultAccessPermission(DefaultAccess.toStdString().c_str());
    class_mydcom.setDefaultLaunchPermission(DefaultLaunch.toStdString().c_str());
    emit signal_recommend("正在设置OPC组件权限");
    class_mydcom.clearOPC("{41EBD53D-36C4-4027-B2B4-09A6E4A362DD}");
    class_mydcom.clearOPC("{13486D44-4821-11D2-A494-3CB306C10000}");
    emit signal_recommend("正在修改用户组");

    QString myusername = class_mydcom.getUserName();

    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"net"<<"localgroup"<<"Distributed COM Users"<<myusername<<"/add");
    p.waitForStarted();
    p.waitForFinished(-1);
    emit signal_recommend("正在设置组策略");


    QFile file(QString("newLOCALPOLICY.inf"));

    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {

        QString content=
R"===(
signature="$CHICAGO$"
Revision=1
[Unicode]
Unicode=yes
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551,*S-1-5-32-562
SeDenyInteractiveLogonRight = Guest
)===";
        QTextStream textStream(&file);
        textStream.setCodec("UTF-16LE");
        textStream<<content;
        file.close();
        p.start("cmd",QStringList()<<"secedit"<<"/configure"<<"/db"<<"secedit.sdb"<<"/cfg"<<"newLOCALPOLICY.inf");
        p.waitForStarted();
        p.waitForFinished(-1);
        p.start("cmd",QStringList()<<"gpupdate"<<"/force");
        p.waitForStarted();
        p.waitForFinished(-1);
        p.start("cmd",QStringList()<<"del"<<"secedit.jfm");
        p.waitForStarted();
        p.waitForFinished(-1);
        p.start("cmd",QStringList()<<"del"<<"secedit.sdb");
        p.waitForStarted();
        p.waitForFinished(-1);
        p.start("cmd",QStringList()<<"del"<<"newLOCALPOLICY.inf");
        p.waitForStarted();
        p.waitForFinished(-1);


    }

    emit signal_recommend("ok");


}
