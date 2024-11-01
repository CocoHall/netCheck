#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTabWidget>
#include <QTableWidget>
#include <QHeaderView>
#include <QPalette>
#include <QCheckBox>
#include <QFont>
#include <QMessageBox>
#include <QFileDialog>
#include <QComboBox>

#include <QDebug>
#include <QRegExp>
#include <QThread>
#include <QThreadPool>
#include <QDir>
#include <QFile>
#include <qmap.h>
#include <QString>
#include <QMetaType>
#include <QStandardItemModel>
#include <QMutex>
#include <QProgressBar>
#include <QPair>
#include <shlobj.h>
#include "mychart.h"
#include "mydcom.h"
#include "myperformance.h"
#include "myping.h"
#include "myinfo.h"
#include "myrecommend.h"
#include "mywireshark.h"
#include "mytotal.h"
#include "mywiresharkcheck.h"
#include "myprocess.h"
#include "rbtableheaderview.h"
#include "mynetchart.h"
#include "myglobal.h"
#include "myunit.h"
//#define DCOM_ENABLE

#define CELL_SIZE 25
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QTableView* table_ping_list;
    QStandardItemModel* pingDataModel;
    QLineEdit* line_targetip;
    QTabWidget* tabWidgets;
    QTableWidget* table_wireshark,*table_process,*table_log,*table_arp;
    QLabel* label_alivecount,*label_alivecountA,*label_alivecountB,*label_alivecountC,*label_count_gb,*label_count_zb,*label_count_db;
    QPushButton *button_pingHidden,*button_ping,*button_ping_save,*button_gather,*button_performance,*button_performance_save;
    QPushButton *button_arp_refresh,*button_wireshark,*button_log_save,*process_save;
#ifdef DCOM_ENABLE
    QPushButton *button_DCOM_recommend,*button_DCOM_refresh,*button_DCOM_apply;
    QTableWidget *table_dcom_result,*table_dcom_access,*table_dcom_lanuchActive,*table_dcom_opc,*table_dcom_authorization;
#endif

    QMap<QString,QCheckBox*> checkbox_gather_sys_map,checkbox_gather_700_map,checkbox_gather_900_map;
    QList<QCheckBox*> checkbox_perform_dir,checkbox_netcard;
//    QLineEdit* line_filter;
    QComboBox* combobox_filter,*combobox_stop;
    QCheckBox* checkbox_A,*checkbox_B,*checkbox_C;
    QLineEdit* line_A,*line_B,*line_C;
    QProgressBar *pingProgressBar;

public:

signals:
   void updateVisible(int index,bool visible);

public slots:
    void pingStart();
    void pingResultUpdate(int node,int type ,int delay,int numOfSend,int numOfRecv);
    void pingSort(int logicalIndex);
    void pingUpdateColor();
    void pingHidden();
    void pingSave();
    void checkboxSelectSysALL(int stat);
    void checkboxSelect900ALL(int stat);
    void checkboxSelect700ALL(int stat);
//    void checkboxSelect(int stat);
    void gatherStart();
    void gatherResultUpdate(QString tag);
    int configSelectLogDir();
    int configSelectWiresharkDir();
    int configSelectInfoDir();
    int configSelectProcessDir();
    int configSelect900ProjectDir();
    void performanceStart();
    void checkBoxPerformUpdate(int stat);
    void performanceSave();

    void dcomRefresh();
    #ifdef DCOM_ENABLE
    void dcomApply();
    void dcomRecommend();
    void recommendFinish(QString tag);
    #endif
    void wiresharkStart();
    void wiresharkUpdateARPFromSys(int stat=0);
    void addLog(QString typeinfo ,QString info,int last=0);

    void updateWiresharkDiag(QString src_type,unsigned char byMediaStatus0,unsigned char byMediaStatus1,unsigned char byLinkStatus0,unsigned char byLinkStatus1,unsigned char byNetSpeed0,unsigned char byNetSpeed1,
                                         unsigned char byDuplex0,unsigned char byDuplex1,unsigned char byBurthenOver0,unsigned char byBurthenOver1,unsigned char byAbnormityNode0,unsigned char byAbnormityNode1,
                                         unsigned char byInterCom,unsigned char byAddrCollision,unsigned char bySntpError,unsigned char byWorkMode);
    void updateWiresharkInfo(int level,QString tag);
    void wiresharkUpdateTotal(int type);
    void wiresharkUpdateARPFromPackets(QString ip,QString mac);
    void wiresharkCheckMAC(QString ip,QString mac);
    void wiresharkLogSave();
    void wiresharkDiag(QString sip_type,long shouldReceived,long hasReceived);
    void processUpdate(QList<QMap<QString,QString>> info);
    void processSort(int logicalIndex);
    void processSave();
    void processSaveMessage(int,QString);

    void showNetChart(int row, int column);



private:
    Ui::MainWindow *ui;
    void drawPing();
    void drawPerformance();
    void drawGather();
    void drawWireshark();
#ifdef DCOM_ENABLE
    void drawDCOM();
    void getSecedit();

    int judgePermission(int value1,QString value2);
    int judgePermission2(int Default,int Restriction);
    int isInGroup(QString username,QString groupname,QString targetGroup,int everyoneIncludeAnonymous);
#endif
    void drawProcess();
    void initSignal();
    void pingThread(QString ipCIDR,int timeout);
    QString getFriendlyStr(QString value);
    void dcomCheck();
    void addResult(QString value);
    int isMulticast(QString inputstr);
    void pingUpdate();
    QString getRandomString(int length);
    QMutex pingResultMutex,processResultMutex;
    long totalMulticast,totalUnicast,totalBoardcast;
    int pingSortType=0;
    int pingSortCol=0;
    int hiddenOffPing=0;
    int pingTotal=0,pingCurrent=0;
    int infoGathed = 0;

    QWidget* widget_performance;
    myperformance* myperformanceclass;
    mydcom* mydcomclass;
    mychart* mychartclass;
    myinfo* myinfoclass;
#ifdef DCOM_ENABLE
    myrecommend* myrecommendclass;
#endif
//    QList<mywireshark*> mywiresharkclasslist;
    mywiresharkCheck* mywiresharkcheckclass;
    myprocess* myprocessclass;




    QThreadPool* qThreadPool1;
    QThreadPool* qThreadPool2;
    QThreadPool* qThreadPool3;

    QList<mynetchart*> mynetchartlist;

    QList<QPair<int,int[5*3]>> pingData;
    /*node:254*/
        /*A网发包 收包 最大时延 最小时延 总时延*/
        /*B网发包 收包 最大时延 最小时延 总时延*/
        /*C网发包 收包 最大时延 最小时延 总时延*/


    QMap<QString,QMap<QString,QString>> DCOMPermission;

    /*
        Administrator : LocalAccessRestriction  :0
                        RemoteAccessRestriction :0
                        LocalAccessDefault
                        RemoteAccessDefault
                        LocalLanuchRestriction
                        RemoteLanuchRestriction
                        LocalLanuchDefault
                        RemoteLanuchDefault
                        LocalActiveRestriction
                        RemoteActiveRestriction
                        LocalActiveDefault
                        RemoteActiveDefault
    */

    QList<QMap<QString,QString>> OpcInfo;

    /*
        [0]   uuid:{41EBD53D-36C4-4027-B2B4-09A6E4A362DD}
              name:SUPCON.SCRTCore
              isexists:true
              accessDefault:false
              launchDefault:false

      */
    QList<QMap<QString,QMap<QString,QString>>> OpcPermission;

    /*
        [0]
            Administrator : LocalAccess  :0
                            RemoteAccess :0
                            LocalLaunch
                            RemoteLaunch
                            LocalActive
                            RemoteActive

      */




};

#endif // MAINWINDOW_H

































