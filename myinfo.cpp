#include "myinfo.h"

myinfo::myinfo()
{
    checklist=nullptr;
}

myinfo::~myinfo()
{
    delete checklist;
}

void myinfo::setList(QStringList* checklist){
    if(this->checklist){
        delete checklist;
        checklist=nullptr;
    }
    this->checklist=checklist;
}

void myinfo::setDirname(QString path,QString path2){
    dirname=path;
    zipDirname=path2;
}




void myinfo::saveARPTable(){
    QString path=dirname+QString("/上位机系统信息/ARP表/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"arp"<<"-a"<<">"<<(path+"arp_a.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveRoute(){
    QString path=dirname+QString("/上位机系统信息/路由信息/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"route"<<"print"<<">"<<(path+"route_print.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"ip"<<"show"<<"route"<<">"<<(path+"netsh_interface_ip_show_route.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveNetcard(){
    QString path=dirname+QString("/上位机系统信息/网卡属性/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"ipconfig"<<"/all"<<">"<<(path+"ipconfig.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"show"<<"interface"<<">"<<(path+"netsh_interface_show_interface.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"ip"<<"show"<<"config"<<">"<<(path+"netsh_interface_ip_show_config.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"ip"<<"show"<<"dnsservers"<<">"<<(path+"netsh_interface_ip_show_dnsservers.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"dump"<<">"<<(path+"netsh_interface_dump.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveFirewall(){
    QString path=dirname+QString("/上位机系统信息/防火墙规则/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"advfirewall"<<"show"<<"allprofiles"<<">"<<(path+"netsh_advfirewall_show_allprofiles.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"advfirewall"<<"firewall"<<"show"<<"rule"<<"name=all"<<">"<<(path+"netsh_advfirewall_firewall_show_rule_name_all.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::savePort(){
    QString path=dirname+QString("/上位机系统信息/端口情况/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"ip"<<"show"<<"tcpconnections"<<">"<<(path+"netsh_interface_ip_show_tcpconnections.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"interface"<<"ip"<<"show"<<"udpconnections"<<">"<<(path+"netsh_interface_ip_show_udpconnections.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netstat"<<"-ano"<<">"<<(path+"netstat_ano.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveTasklist(){
    QString path=dirname+QString("/上位机系统信息/进程信息/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"tasklist"<<"/v"<<">"<<(path+"tasklist.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"PROCESS"<<">"<<(path+"wmic_PROCESS.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

}

void myinfo::saveDCOM(){
    QString path=dirname+QString("/上位机系统信息/DCOM配置/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DCOM"<<"/f"<<"MachineAccessRestriction"<<">"<<(path+"reg_DCOM.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DCOM"<<"/f"<<"MachineLaunchRestriction"<<">>"<<(path+"reg_DCOM.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole"<<"/f"<<"DefaultAccessPermission"<<">"<<(path+"reg_DefaultAccessPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole"<<"/f"<<"DefaultLaunchPermission"<<">"<<(path+"reg_DefaultLaunchPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole"<<"/f"<<"MachineAccessRestriction"<<">"<<(path+"reg_MachineAccessRestriction.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole"<<"/f"<<"MachineLaunchRestriction"<<">"<<(path+"reg_MachineLaunchRestriction.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_CLASSES_ROOT\\AppID\\{13486D44-4821-11D2-A494-3CB306C10000}"<<"/f"<<"DefaultAccessPermission"<<">"<<(path+"OpcEnum_DefaultAccessPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_CLASSES_ROOT\\AppID\\{13486D44-4821-11D2-A494-3CB306C10000}"<<"/f"<<"DefaultLaunchPermission"<<">"<<(path+"OpcEnum_DefaultLaunchPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_CLASSES_ROOT\\AppID\\{41EBD53D-36C4-4027-B2B4-09A6E4A362DD}"<<"/f"<<"DefaultAccessPermission"<<">"<<(path+"SUPCON_SCRTCore_DefaultAccessPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKEY_CLASSES_ROOT\\AppID\\{41EBD53D-36C4-4027-B2B4-09A6E4A362DD}"<<"/f"<<"DefaultLaunchPermission"<<">"<<(path+"SUPCON_SCRTCore_DefaultLaunchPermission.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveService(){
    QString path=dirname+QString("/上位机系统信息/系统服务信息/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"WMIC"<<"SERVICE"<<"GET"<<"Name,DisplayName,PathName,ProcessId,StartMode,StartName,State,ServiceType"<<">"<<(path+"wmic_service.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveKB(){
    QString path=dirname+QString("/上位机系统信息/补丁情况/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"WMIC"<<"qfe"<<">"<<(path+"wmic_qfe.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveSoft(){
    QString path=dirname+QString("/上位机系统信息/已安装软件/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"WMIC"<<"product"<<">"<<(path+"wmic_product.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveEvent(){
    QString path=dirname+QString("/上位机系统信息/系统日志/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wevtutil"<<"epl"<<"System"<<(path+"System.evtx"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wevtutil"<<"epl"<<"Security"<<(path+"Security.evtx"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wevtutil"<<"epl"<<"Application"<<(path+"Application.evtx"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wevtutil"<<"epl"<<"Setup"<<(path+"Setup.evtx"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveDNS(){
    QString path=dirname+QString("/上位机系统信息/DNS缓存/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"ipconfig"<<"/displaydns"<<">"<<(path+"ipconfig_displaydns.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"copy"<<"%windir%\\System32\\drivers\\etc\\hosts"<<(path+"hosts"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveSchtasks(){
    QString path=dirname+QString("/上位机系统信息/计划任务/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"SCHTASKS"<<"/query"<<"/v"<<">"<<(path+"SCHTASKS.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveStartup(){
    QString path=dirname+QString("/上位机系统信息/启动项/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"STARTUP"<<">"<<(path+"wmic_startup.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveShare(){
    QString path=dirname+QString("/上位机系统信息/文件共享/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"SHARE"<<">"<<(path+"wmic_share.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveSecedit(){
    QString path=dirname+QString("/上位机系统信息/组策略/");
    myunit::mkdir(path);
    path=path.replace('/','\\');
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"secedit"<<"/export"<<"/cfg"<<(path+"LOCALPOLICY.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::savePower(){
    QString path=dirname+QString("/上位机系统信息/其他/电源信息/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"powercfg"<<"/Q"<<">"<<(path+"powercfg.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"cd"<<path<<"&&"<<"powercfg"<<"/SYSTEMSLEEPDIAGNOSTICS");
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"cd"<<path<<"&&"<<"powercfg"<<"/SYSTEMPOWERREPORT");
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveSysteminfo(){
    QString path=dirname+QString("/上位机系统信息/系统信息/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"systeminfo"<<">"<<(path+"systeminfo.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"SET"<<">"<<(path+"environment.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"driverquery"<<"/v"<<">"<<(path+"driverquery.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"cpu"<<"get"<<"LoadPercentage,Name,NumberOfCores,NumberOfEnabledCore,NumberOfLogicalProcessors"<<">"<<(path+"cpu.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"logicaldisk"<<"get"<<"Compressed,Description,DeviceID,DriveType,FileSystem,FreeSpace,InstallDate,MediaType,Size,VolumeSerialNumber"<<">"<<(path+"logicaldisk.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"ver"<<">"<<(path+"ver.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"systeminfo"<<">"<<(path+"systeminfo.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"query"<<"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"<<"/f"<<"ReleaseId"<<">"<<(path+"CurrentVersion.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveAccount(){
    QString path=dirname+QString("/上位机系统信息/系统账号信息/用户/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"USERACCOUNT"<<"get"<<"name");
    p.waitForStarted();
    p.waitForFinished(-1);
    QString result = p.readAllStandardOutput();
    QRegExp rxlen("(.+)\\n");
    rxlen.setMinimal(true);
    int pos=0;
    while ((pos = rxlen.indexIn(result, pos)) >= 0) {

        if(rxlen.capturedTexts().size()>1){
            QString name=rxlen.capturedTexts()[1].trimmed();

            if(name!="Name" && name!=""){
                QProcess p(nullptr);
                p.start("cmd",QStringList()<<"/c"<<"net"<<"user"<<name<<">"<<(path+name+".log"));
                p.waitForStarted();
                p.waitForFinished(-1);
            }
        }

        pos += rxlen.matchedLength();
    }
}

void myinfo::saveGroup(){
    QString path=dirname+QString("/上位机系统信息/系统账号信息/用户组/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"group"<<"get"<<"name");
    p.waitForStarted();
    p.waitForFinished(-1);
    QString result = p.readAllStandardOutput();
    QRegExp rxlen("(.+)\\n");
    rxlen.setMinimal(true);
    int pos=0;
    while ((pos = rxlen.indexIn(result, pos)) >= 0 ) {
        if(rxlen.capturedTexts().size()>1){
            QString name=rxlen.capturedTexts()[1].trimmed();
            if(name!="Name" && name!=""){
                QProcess p(nullptr);
                p.start("cmd",QStringList()<<"/c"<<"net"<<"localgroup"<<name<<">"<<(path+name+".log"));
                p.waitForStarted();
                p.waitForFinished(-1);
            }
        }

        pos += rxlen.matchedLength();
    }
}

void myinfo::saveRDP(){
    QString path=dirname+QString("/上位机系统信息/其他/远程桌面/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"REG"<<"QUERY"<<"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"<<"/v"<<"fDenyTSConnections"<<">"<<(path+"RDP.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"REG"<<"QUERY"<<"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"<<"/v"<<"PortNumber"<<">"<<(path+"RDPport.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveRecent(){
    QString path=dirname+QString("/上位机系统信息/其他/最近打开/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"REG"<<"QUERY"<<"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"<<">"<<(path+"Recent.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"REG"<<"QUERY"<<"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"<<">>"<<(path+"Recent.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"REG"<<"QUERY"<<"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"<<">>"<<(path+"Recent.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"dir"<<"%AppData%\\Microsoft\\Windows\\Recent"<<">>"<<(path+"Recent.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveSession(){
    QString path=dirname+QString("/上位机系统信息/其他/会话/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"qwinsta"<<">"<<(path+"qwinsta.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"query"<<"user"<<">>"<<(path+"qwinsta.log"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::saveOther(){
    QString path=dirname+QString("/上位机系统信息/其他/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"path"<<"Win32_OperatingSystem"<<"get"<<"LastBootUpTime"<<">"<<(path+"LastBootUpTime.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"wmic"<<"bios"<<">"<<(path+"bios.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"netsh"<<"wlan"<<"show"<<"all"<<">"<<(path+"wifi.log"));
    p.waitForStarted();
    p.waitForFinished(-1);

}

void myinfo::saveReg(){
    QString path=dirname+QString("/上位机系统信息/注册表/");
    myunit::mkdir(path);
    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"reg"<<"export"<<"HKEY_CLASSES_ROOT"<<(path+"HKEY_CLASSES_ROOT.reg"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"export"<<"HKEY_CURRENT_USER"<<(path+"HKEY_CURRENT_USER.reg"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"export"<<"HKEY_LOCAL_MACHINE"<<(path+"HKEY_LOCAL_MACHINE.reg"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"export"<<"HKEY_USERS"<<(path+"HKEY_USERS.reg"));
    p.waitForStarted();
    p.waitForFinished(-1);

    p.start("cmd",QStringList()<<"/c"<<"reg"<<"export"<<"HKEY_CURRENT_CONFIG"<<(path+"HKEY_CURRENT_CONFIG.reg"));
    p.waitForStarted();
    p.waitForFinished(-1);
}

void myinfo::getICSinfo(){
    QSettings settings("HKEY_LOCAL_MACHINE\\SOFTWARE\\SUPCON\\VisualField3.00\\HMI",QSettings::NativeFormat);
    QSettings settings2("HKEY_CURRENT_USER\\SOFTWARE\\SUPCON\\VisualField3.00\\HMI",QSettings::NativeFormat);

    CfgRefPath = settings.value("CfgRefPath", "").toString();
    CfgRootPath = settings.value("CfgRootPath", "").toString();
    CfgSvrPath = settings.value("CfgSvrPath", "").toString();
    IntallDirectory = settings.value("IntallDirectory", "").toString();
    RunRefPath = settings.value("RunRefPath", "").toString();
    RunRootPath = settings.value("RunRootPath", "").toString();

    if(CfgRefPath=="") CfgRefPath= settings2.value("CfgRefPath", "D:\\ECSDataRef").toString();
    if(CfgRootPath=="") CfgRootPath= settings2.value("CfgRootPath", "D:\\ECSData").toString();
    if(CfgSvrPath=="") CfgSvrPath= settings2.value("CfgSvrPath", "D:\\SUPCON_PROJECT").toString();
    if(IntallDirectory=="") IntallDirectory= settings2.value("IntallDirectory", "C:\\VisualField4").toString();
    if(RunRefPath=="") RunRefPath= settings2.value("RunRefPath", "D:\\ECSRunRef").toString();
    if(RunRootPath=="") RunRootPath= settings2.value("RunRootPath", "D:\\ECSRun").toString();
}

void myinfo::save700Project(){
    QString path=dirname+QString("/700系统/PROJCET");
    myunit::mkdir(path);
    myunit::mkdir(path+"/ECSDataRef");
    myunit::mkdir(path+"/ECSData");
    myunit::mkdir(path+"/SUPCON_PROJECT");
    myunit::mkdir(path+"/ECSRunRef");
    myunit::mkdir(path+"/ECSRun");

    myunit::copyDir(CfgRefPath,path+"/ECSDataRef",0);
    myunit::copyDir(CfgRootPath,path+"/ECSData",0);
    myunit::copyDir(CfgSvrPath,path+"/SUPCON_PROJECT",0);
    myunit::copyDir(RunRefPath,path+"/ECSRunRef",0);
    myunit::copyDir(RunRootPath,path+"/ECSRun",0);

}

void myinfo::saveICSVF(){
    QString path2=dirname+QString("/700系统/Visualfield4");
    myunit::mkdir(path2);
    myunit::copyDir(IntallDirectory,path2,1);
}

void myinfo::save700TimeSync(){
    QString path3=dirname+QString("/700系统/TimeSync");

    QSettings settings3("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{E01D07CF-13DD-4995-A4B4-CAB6A3D7C92F}",QSettings::NativeFormat);
    QString timeSyncInstallLocation = settings3.value("InstallLocation", "C:\\Program Files (x86)\\Common Files\\SUPCON\\Shared\\TimeSync").toString();
    if(timeSyncInstallLocation.length()>0){
        myunit::mkdir(path3);
        myunit::copyDir(timeSyncInstallLocation,path3,1);
    }
}

void myinfo::saveICSDCS(){

    char defaultConfig[MAX_PATH] = {0};
    GetPrivateProfileStringA("config", "default", "", defaultConfig,MAX_PATH,(RunRootPath+"\\Database.ini").toStdString().c_str());
    if(strlen(defaultConfig)==0)
    {
        return ;
    }
    QString defaultProjectXmlFile=RunRootPath+"\\"+defaultConfig+"\\Project.xml";
    QFile xmlfile(defaultProjectXmlFile);
    if (!xmlfile.open(QFile::ReadOnly | QFile::Text)) {
        return ;
    }
    QString errorStr;
    int errorLine;
    int errorColumn;

    QDomDocument doc;
    if (!doc.setContent(&xmlfile, false, &errorStr, &errorLine, &errorColumn))
    {
        return ;
    }
    QStringList dcsIPs;
    QDomElement project = doc.documentElement();
    if(project.tagName().toLower()!="project")return;

    QDomNode controls = project.firstChild();
    while (!controls.isNull())
    {
        if (controls.toElement().tagName().toLower() == "control")
        {
            QDomNode ctrlareas = controls.firstChild();
            while (!ctrlareas.isNull())
            {
                if (ctrlareas.toElement().tagName().toLower() == "ctrlarea" )
                {
                    QString tmp = ctrlareas.toElement().attribute("ID");
                    if(tmp.length()==10){
                        tmp=tmp.mid(6,2);
                        int tmpint = tmp.toInt(nullptr,16);

                        QDomNode ctrlstations = ctrlareas.firstChild();
                        while (!ctrlstations.isNull())
                        {
                            if (ctrlstations.toElement().tagName().toLower() == "ctrlstation" )
                            {
                                QString addr = ctrlstations.toElement().attribute("addr");
                                QString ip = "172.20."+QString::number(tmpint)+"."+addr;
                                dcsIPs.append(ip);

                            }
                            ctrlstations = ctrlstations.nextSibling();
                        }
                    }
                }
                ctrlareas = ctrlareas.nextSibling();
            }
        }

        controls = controls.nextSibling();
    }

    if(dcsIPs.length()==0)return;
    QString path=dirname+QString("/700系统/DCS");
    myunit::mkdir(path);

    qsrand(QDateTime::currentDateTime().toTime_t());
    char SeqNum =qrand()%255;
    QByteArray tail;
    quint16 port = 0x3000;
    tail.resize(8);
    tail[0] = 'S';
    tail[1] = 'C';
    tail[2] = 'n';
    tail[3] = 'e';
    tail[4] = 't';
    tail[5] = '1';
    tail[6] = '0';
    tail[7] = '0';
    for(int i=0;i<dcsIPs.length();i++){

        QFile file(path+QString("/"+dcsIPs[i]+".log"));

        if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            continue;
        }

        QTextStream textStream(&file);
        QString Equipment_Type="";
        QString CPU_hard="";
        QString SCnet_hard="";
        QString IO_hard="";
        QString CPU_soft="";
        QString SCnet_soft="";
        QString IO_soft="";
        QString serial_number="";
        QString date="";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看设备类别\n");
        Equipment_Type=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x40,0x02);
        textStream<<Equipment_Type<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看控制CPU底板硬件版本信息\n");
        CPU_hard=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x44,0x02);
        textStream<<CPU_hard<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看SCNET背板硬件版本信息\n");
        SCnet_hard=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x46,0x02);
        textStream<<SCnet_hard<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看I/O背板硬件版本信息\n");
        IO_hard=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x48,0x02);
        textStream<<IO_hard<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看控制CPU软件版本信息\n");
        CPU_soft=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x4C,0x02);
        textStream<<CPU_soft<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看SCNET软件版本信息\n");
        SCnet_soft=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x4E,0x02);
        textStream<<SCnet_soft<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看I/O软件版本信息\n");
        IO_soft=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x50,0x02);
        textStream<<IO_soft<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看出厂序列号\n");
        serial_number=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x60,0x20);
        textStream<<serial_number<<"\n";

        textStream<<QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")<<QString("\t下发0x67命令，查看生产日期\n");
        date=getDCSInfo(0x3100,dcsIPs[i],port,++SeqNum,0x80,0x08);
        textStream<<date<<"\n";

        file.close();
    }

}

void myinfo::run(){

    if(checklist->contains("arp")){
        emit signal_gather("正在收集ARP信息");
        saveARPTable();
    }
    if(checklist->contains("route")){
        emit signal_gather("正在收集路由信息");
        saveRoute();
    }
    if(checklist->contains("netcard")){
        emit signal_gather("正在收集网卡信息");
        saveNetcard();
    }
    if(checklist->contains("firewall")){
        emit signal_gather("正在收集防火墙信息");
        saveFirewall();
    }
    if(checklist->contains("process")){
        emit signal_gather("正在收集进程信息");
        saveTasklist();
    }
    if(checklist->contains("dcom")){
        emit signal_gather("正在收集DCOM配置");
        saveDCOM();
    }
    if(checklist->contains("service")){
        emit signal_gather("正在收集服务信息");
        saveService();
    }
    if(checklist->contains("kb")){
        emit signal_gather("正在收集补丁信息");
        saveKB();
    }
    if(checklist->contains("systeminfo")){
        emit signal_gather("正在收集系统信息");
        saveSysteminfo();
    }
    if(checklist->contains("regedit")){
        emit signal_gather("正在导出全部注册表");
        saveReg();
    }
    if(checklist->contains("soft")){
        emit signal_gather("正在收集已安装软件");
        saveSoft();
    }
    if(checklist->contains("event")){
        emit signal_gather("正在收集系统日志");
        saveEvent();
    }
    if(checklist->contains("port")){
        emit signal_gather("正在收集端口");
        savePort();
    }
    if(checklist->contains("account")){
        emit signal_gather("正在收集账户信息");
        saveAccount();
        saveGroup();
    }
    if(checklist->contains("dns")){
        emit signal_gather("正在收集DNS缓存");
        saveDNS();
    }
    if(checklist->contains("schtasks")){
        emit signal_gather("正在收集任务计划");
        saveSchtasks();
    }
    if(checklist->contains("smb")){
        emit signal_gather("正在收集共享信息");
        saveShare();
    }
    if(checklist->contains("startup")){
        emit signal_gather("正在收集启动项");
        saveStartup();
    }
    if(checklist->contains("gpedit")){
        emit signal_gather("正在收集组策略");
        saveSecedit();
    }
    getICSinfo();
    if(checklist->contains("ics_project")){
        emit signal_gather("正在收集控制系统组态工程文件");
        save700Project();
    }
    if(checklist->contains("ics_vf")){
        emit signal_gather("正在收集控制系统VF配置和日志");
        saveICSVF();
    }
    if(checklist->contains("ics_timesync")){
        emit signal_gather("正在收集700系统时钟同步日志");
        save700TimeSync();
    }
    if(checklist->contains("ics_dcs")){
        emit signal_gather("正在收集控制系统控制器信息");
        saveICSDCS();
    }
    if(checklist->contains("other")){
        emit signal_gather("正在收集其他/电源信息");
        savePower();
        emit signal_gather("正在收集其他/远程信息");
        saveRDP();
        emit signal_gather("正在收集其他/近期记录");
        saveRecent();
        emit signal_gather("正在收集其他/会话信息");
        saveSession();
        emit signal_gather("正在收集其他信息");
        saveOther();
    }

    if(checklist->contains("900_project")){
        emit signal_gather("正在收集SafeContrix组态工程文件");
        save900Project();
    }
    if(checklist->contains("900_scada")){
        emit signal_gather("正在收集SCADA组态工程文件");
        saveScadaProject();
    }
    if(checklist->contains("900_timesync")){
        emit signal_gather("正在收集900系统时钟同步日志");
        save900TimeSync();
    }

    emit signal_gather("正在打包");
    DWORD usernameSize=MAX_COMPUTERNAME_LENGTH + 1;
    char username[MAX_COMPUTERNAME_LENGTH + 1]={0};

    GetComputerNameA(username,&usernameSize);
    QString qusername(username);
    QString filename=zipDirname + QDir::separator() +qusername+"_"+QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")+".zip";
    JlCompress::compressDir(filename,dirname);
    emit signal_gather("ok");
}




QString myinfo::getDCSInfo(quint16 srcPort,QString dstIP ,quint16 dstPort,char SeqNum,char offerset,char datalength){

    QByteArray tail;
    tail.resize(8);
    tail[0] = 'S';
    tail[1] = 'C';
    tail[2] = 'n';
    tail[3] = 'e';
    tail[4] = 't';
    tail[5] = '1';
    tail[6] = '0';
    tail[7] = '0';

    QUdpSocket m_Socket;
    m_Socket.bind(srcPort);

    QByteArray header;
    header.resize(6);
    header[0]=0x01;
    header[1]=0x67;
    header[2]=0x00;
    header[3]=0x00;
    header[4]=0x00;
    header[5]=0x00;

    QByteArray parameter;
    parameter.resize(8);
    parameter[0] = 0x00;
    parameter[1] = 0x00;
    parameter[2] = 0x00;
    parameter[3] = 0x00;
    parameter[4] = 0x00;
    parameter[5] = 0x00;
    parameter[6] = 0x01;
    parameter[7] = 0x00;

    QHostAddress dcsIP(dstIP);
    QByteArray senddata;
    header[4]=SeqNum;
    parameter[0] = offerset;
    parameter[4] = datalength;
    senddata=header+parameter+tail;

    m_Socket.writeDatagram(senddata, dcsIP, dstPort);

    uint startTime=QDateTime::currentDateTime().toTime_t();
    QString result="";
    while(QDateTime::currentDateTime().toTime_t()-startTime<2){
        if(m_Socket.hasPendingDatagrams()){
            QByteArray datagram; //拥于存放接收的数据报
            datagram.resize(m_Socket.pendingDatagramSize());
            m_Socket.readDatagram(datagram.data(),datagram.size(),&dcsIP,&dstPort);
            if(datagram.size()==senddata.size()+datalength){
                int flag=0;
                for(int j=0;j<senddata.length()-tail.length();j++){
                    if(senddata[j]!=datagram[j]){
                        flag=1;
                        break;
                    }
                }
                if(flag)continue;
                QByteArray tmp;
                tmp.resize(parameter[4]);

                for(int j=0;j<parameter[4];j++){
                    tmp[j]=datagram[senddata.size()-tail.length()+j];
                }
                result=tmp.toHex();
                break;
            }
        }
    }
    m_Socket.close();
    return result;
}

void myinfo::saveScadaProject(){
    QString path=dirname+QString("/900系统/Scada");
    myunit::mkdir(path);
    myunit::mkdir(path+"/ECSDataRef");
    myunit::mkdir(path+"/ECSData");
    myunit::mkdir(path+"/SUPCON_PROJECT");
    myunit::mkdir(path+"/ECSRunRef");
    myunit::mkdir(path+"/ECSRun");

    myunit::copyDir(CfgRefPath,path+"/ECSDataRef",0);
    myunit::copyDir(CfgRootPath,path+"/ECSData",0);
    myunit::copyDir(CfgSvrPath,path+"/SUPCON_PROJECT",0);
    myunit::copyDir(RunRefPath,path+"/ECSRunRef",0);
    myunit::copyDir(RunRootPath,path+"/ECSRun",0);

}

void myinfo::save900TimeSync(){
    QString path3=dirname+QString("/900系统/TimeSync");

    QSettings settings3("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{E01D07CF-13DD-4995-A4B4-CAB6A3D7C92F}",QSettings::NativeFormat);
    QString timeSyncInstallLocation = settings3.value("InstallLocation", "C:\\Program Files (x86)\\Common Files\\SUPCON\\Shared\\TimeSync").toString();
    if(timeSyncInstallLocation.length()>0){
        myunit::mkdir(path3);
        myunit::copyDir(timeSyncInstallLocation,path3,1);
    }
}


void myinfo::save900Project(){
    QString path=dirname+QString("/900系统/Project");
    myunit::mkdir(path);

    QFileInfo fileInfo(myglobal::project_900_sisPrj);
    QFile::copy(myglobal::project_900_sisPrj, path+QDir::separator()+fileInfo.fileName());

    QString sisPrjName = fileInfo.fileName().replace(".sisPrj","");//文件夹名

    QString tmp=fileInfo.path()+QDir::separator()+sisPrjName;              //完整文件夹路径

    QString path2=path+QDir::separator()+sisPrjName;

    myunit::mkdir(path2);

    myunit::copyDir(tmp,path2,0);
}





















