#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <type_traits>

#define CHECKBOX_COL_NUM 3

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    tabWidgets = new QTabWidget();

    mywiresharkcheckclass=new mywiresharkCheck();

    myperformanceclass=new myperformance();
    mydcomclass=new mydcom();
    myinfoclass=new myinfo();

#ifdef DCOM_ENABLE
    myrecommendclass=new myrecommend();
#endif
    myprocessclass=new myprocess();
    qThreadPool1 =new QThreadPool();
    qThreadPool1->setMaxThreadCount(30);
    qThreadPool2 =new QThreadPool();
    qThreadPool2->setMaxThreadCount(30);
    qThreadPool3 =new QThreadPool();
    qThreadPool3->setMaxThreadCount(30);

    drawPing();
    drawWireshark();
    drawGather();
#ifdef DCOM_ENABLE
    drawDCOM();
#endif
    drawPerformance();
    drawProcess();
    ui->horizontalLayout->addWidget(tabWidgets);
    initSignal();
    if(!IsUserAnAdmin()){
//        QMessageBox::warning(this,"提示",QString("请使用管理员权限登录！"));
    }


}

void MainWindow::initSignal(){
    myglobal::info_save_dir = QCoreApplication::applicationDirPath()+QString("/info");
    myglobal::info_zip_save_dir = myglobal::info_save_dir;
    myglobal::log_save_dir = QCoreApplication::applicationDirPath()+QString("/log");
    myglobal::wireshark_save_dir = QCoreApplication::applicationDirPath()+QString("/packets");
    myglobal::process_save_dir = QCoreApplication::applicationDirPath()+QString("/process");
    myglobal::project_900_sisPrj = "D:/TCSData";

    qRegisterMetaType<QList<QMap<QString,QString>>>("QList<QMap<QString,QString>>");
    connect(button_ping,&QPushButton::clicked,this,&MainWindow::pingStart);
    connect(button_ping_save,&QPushButton::clicked,this,&MainWindow::pingSave);
    connect(checkbox_gather_sys_map.find("checkSysAll").value(),&QCheckBox::stateChanged,this,&MainWindow::checkboxSelectSysALL);
    connect(checkbox_gather_700_map.find("check700All").value(),&QCheckBox::stateChanged,this,&MainWindow::checkboxSelect700ALL);
    connect(checkbox_gather_900_map.find("check900All").value(),&QCheckBox::stateChanged,this,&MainWindow::checkboxSelect900ALL);
//    QMap<QString,QCheckBox*>::iterator iter;
//    for (iter = checkbox_gather_sys_map.begin(); iter != checkbox_gather_sys_map.end();++iter)
//    {
//        if(iter.key()=="checkSysAll")continue;
//        connect(iter.value(),&QCheckBox::stateChanged,this,&MainWindow::checkboxSelect);
//    }


    for(int i=0;i<checkbox_perform_dir.length();i++){
        connect(checkbox_perform_dir[i],&QCheckBox::stateChanged,this,&MainWindow::checkBoxPerformUpdate);
    }
    connect(button_gather,&QPushButton::clicked,this,&MainWindow::gatherStart);
    connect(myinfoclass,&myinfo::signal_gather,this,&MainWindow::gatherResultUpdate);
    connect(button_performance,&QPushButton::clicked,this,&MainWindow::performanceStart);

    connect(myperformanceclass,&myperformance::signal_performance,mychartclass,&mychart::updateData);
    connect(myperformanceclass,&myperformance::signal_performance_updateMaxY,mychartclass,&mychart::updateMaxY);
    connect(this,&MainWindow::updateVisible,mychartclass,&mychart::setVisible);
    connect(button_performance_save,&QPushButton::clicked,this,&MainWindow::performanceSave);

    #ifdef ENABLE_DCOM
    connect(button_DCOM_refresh,&QPushButton::clicked,this,&MainWindow::dcomRefresh);
    connect(button_DCOM_apply,&QPushButton::clicked,this,&MainWindow::dcomApply);
    connect(button_DCOM_recommend,&QPushButton::clicked,this,&MainWindow::dcomRecommend);
    connect(myrecommendclass,&myrecommend::signal_recommend,this,&MainWindow::recommendFinish);
    #endif

    connect(button_wireshark,&QPushButton::clicked,this,&MainWindow::wiresharkStart);
    connect(button_arp_refresh,&QPushButton::clicked,this,&MainWindow::wiresharkUpdateARPFromSys);
    connect(button_log_save,&QPushButton::clicked,this,&MainWindow::wiresharkLogSave);
    connect(mywiresharkcheckclass,&mywiresharkCheck::signal_lossRate,this,&MainWindow::wiresharkDiag);
    connect(table_wireshark,&QTableWidget::cellDoubleClicked,this,&MainWindow::showNetChart);

    connect(myprocessclass,&myprocess::signal_process,this,&MainWindow::processUpdate);
    connect(myprocessclass,&myprocess::signal_processSave,this,&MainWindow::processSaveMessage);

    connect(button_pingHidden,&QPushButton::clicked,this,&MainWindow::pingHidden);

    connect(process_save,&QPushButton::clicked,this,&MainWindow::processSave);
    myprocessclass->start();
}

void MainWindow::pingSort(int logicalIndex){
    pingResultMutex.lock();
    table_ping_list->sortByColumn(logicalIndex);
    pingResultMutex.unlock();
}

MainWindow::~MainWindow()
{
    myprocessclass->active=0;
    myglobal::pingActive=0;
    if(myperformanceclass->getActive()){
        myperformanceclass->setActive(0);
        Sleep(1000);
    }
    delete mydcomclass;

    delete myinfoclass;
#ifdef ENABLE_DCOM
    delete myrecommendclass;
#endif
    delete myperformanceclass;
    delete qThreadPool1;
    delete qThreadPool2;
    delete qThreadPool3;
    delete ui;
}

void MainWindow::drawPing(){
    QVBoxLayout* layout_ping = new QVBoxLayout();
    layout_ping->setMargin(30);
    layout_ping->setAlignment(Qt::AlignTop);

    QHBoxLayout* layout_Anet = new QHBoxLayout();
    checkbox_A = new QCheckBox("控制网A");
    checkbox_A->setMinimumWidth(320);
    checkbox_A->setChecked(true);
    line_A = new QLineEdit();
    line_A->setPlaceholderText("172.20.0");
    line_A->setText("172.20.0");
    layout_Anet->addWidget(checkbox_A);
    layout_Anet->addWidget(line_A);

    QHBoxLayout* layout_Bnet = new QHBoxLayout();
    checkbox_B = new QCheckBox("控制网B");
    checkbox_B->setMinimumWidth(320);
    checkbox_B->setChecked(true);
    line_B = new QLineEdit();
    line_B->setPlaceholderText("172.21.0");
    line_B->setText("172.21.0");
    layout_Bnet->addWidget(checkbox_B);
    layout_Bnet->addWidget(line_B);

    QHBoxLayout* layout_Cnet = new QHBoxLayout();
    checkbox_C = new QCheckBox("信息网");
    checkbox_C->setMinimumWidth(320);
    checkbox_C->setChecked(true);
    line_C = new QLineEdit();
    line_C->setPlaceholderText("172.30.0");
    line_C->setText("172.30.0");
    layout_Cnet->addWidget(checkbox_C);
    layout_Cnet->addWidget(line_C);

    layout_ping->addLayout(layout_Anet);
    layout_ping->addLayout(layout_Bnet);
    layout_ping->addLayout(layout_Cnet);

    QHBoxLayout* layout_targetip = new QHBoxLayout();
    QLabel* label_targetip = new QLabel();
    label_targetip->setText("待检测节点范围（1-100,150-200,250,254）");
    label_targetip->setMinimumWidth(320);
    line_targetip = new QLineEdit();
    line_targetip->setPlaceholderText("1-100,150-200,250,254");
    line_targetip->setText("1-254");
    layout_targetip->addWidget(label_targetip);
    layout_targetip->addWidget(line_targetip);

    layout_ping->addLayout(layout_targetip);



    RbTableHeaderView* hHead = new RbTableHeaderView(Qt::Horizontal,2,16);
    //RbTableHeaderView* vHead = new RbTableHeaderView(Qt::Vertical,4,3);
    QAbstractItemModel* hModel = hHead->model();
    //QAbstractItemModel* vModel = vHead->model();
    pingDataModel = new QStandardItemModel;

    hHead->setSpan(0,0,2,1);
    hHead->setSpan(0,1,1,5);
    hHead->setSpan(0,6,1,5);
    hHead->setSpan(0,11,1,5);



    hModel->setData(hModel->index(0,0),QString("节点"),Qt::DisplayRole);
    hModel->setData(hModel->index(0,1),QString("控制网A"),Qt::DisplayRole);
    hModel->setData(hModel->index(0,6),QString("控制网B"),Qt::DisplayRole);
    hModel->setData(hModel->index(0,11),QString("信息网"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,1),QString("最大时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,2),QString("最小时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,3),QString("平均时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,4),QString("收包/发包"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,5),QString("丢包率"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,6),QString("最大时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,7),QString("最小时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,8),QString("平均时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,9),QString("收包/发包"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,10),QString("丢包率"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,11),QString("最大时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,12),QString("最小时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,13),QString("平均时延"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,14),QString("收包/发包"),Qt::DisplayRole);
    hModel->setData(hModel->index(1,15),QString("丢包率"),Qt::DisplayRole);



    hHead->setRowHeight(0,CELL_SIZE);
    hHead->setRowHeight(1,CELL_SIZE);

    hHead->setSectionsClickable(true);
    connect(hHead,&RbTableHeaderView::sectionClicked,this,&MainWindow::pingSort);

//    hHead->setCellBackgroundColor(hModel->index(0,0),0xcfcfcf);
//    hHead->setCellBackgroundColor(hModel->index(0,1),0xcfcfcf);


    table_ping_list = new QTableView(this);
    table_ping_list->setModel(pingDataModel);
    table_ping_list->setHorizontalHeader(hHead);

    table_ping_list->setColumnWidth(0,50);
    table_ping_list->setColumnWidth(1,100);
    table_ping_list->setColumnWidth(2,100);
    table_ping_list->setColumnWidth(3,100);
    table_ping_list->setColumnWidth(4,100);
    table_ping_list->setColumnWidth(5,100);
    table_ping_list->setColumnWidth(6,100);
    table_ping_list->setColumnWidth(7,100);
    table_ping_list->setColumnWidth(8,100);
    table_ping_list->setColumnWidth(9,100);
    table_ping_list->setColumnWidth(10,100);
    table_ping_list->setColumnWidth(11,100);
    table_ping_list->setColumnWidth(12,100);
    table_ping_list->setColumnWidth(13,100);
    table_ping_list->setColumnWidth(14,100);
    table_ping_list->setColumnWidth(15,100);

    table_ping_list->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_ping_list->verticalHeader()->setVisible(false);
    table_ping_list->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_ping_list->setSelectionMode(QAbstractItemView::NoSelection);



    //时延的注释
    QVBoxLayout* layout_vping1 = new QVBoxLayout();
    layout_vping1->setAlignment(Qt::AlignTop);
    layout_vping1->addStretch(1);

    QLabel* label3 = new QLabel();
    label3->setMaximumWidth(20);
    label3->setMinimumWidth(20);

    QPalette* label_palette3 = new QPalette();
    label_palette3->setColor(QPalette::Background, QColor(0, 255, 0));
    label3->setAutoFillBackground(true);
    label3->setPalette(*label_palette3);

    QLabel* label3_2 = new QLabel();
    label3_2->setText("时延小于50ms");

    QHBoxLayout* layout_hlayout3 = new QHBoxLayout();
    layout_hlayout3->addWidget(label3);
    layout_hlayout3->addWidget(label3_2);
    layout_vping1->addLayout(layout_hlayout3);

    QLabel* label4 = new QLabel();
    label4->setMaximumWidth(20);
    label4->setMinimumWidth(20);

    QPalette* label_palette4 = new QPalette();
    label_palette4->setColor(QPalette::Background, QColor(255, 255, 0));
    label4->setAutoFillBackground(true);
    label4->setPalette(*label_palette4);

    QLabel* label4_2 = new QLabel();
    label4_2->setText("时延在50~100ms之间");

    QHBoxLayout* layout_hlayout4 = new QHBoxLayout();
    layout_hlayout4->addWidget(label4);
    layout_hlayout4->addWidget(label4_2);
    layout_vping1->addLayout(layout_hlayout4);

    QLabel* label5 = new QLabel();
    label5->setMaximumWidth(20);
    label5->setMinimumWidth(20);

    QPalette* label_palette5 = new QPalette();
    label_palette5->setColor(QPalette::Background, QColor(191, 205, 219));
    label5->setAutoFillBackground(true);
    label5->setPalette(*label_palette5);

    QLabel* label5_2 = new QLabel();
    label5_2->setText("时延大于100ms");

    QHBoxLayout* layout_hlayout5 = new QHBoxLayout();
    layout_hlayout5->addWidget(label5);
    layout_hlayout5->addWidget(label5_2);
    layout_vping1->addLayout(layout_hlayout5);

    QLabel* label6 = new QLabel();
    label6->setMaximumWidth(20);
    label6->setMinimumWidth(20);
    QPalette* label_palette6 = new QPalette();
    label_palette6->setColor(QPalette::Background, QColor(192, 192, 192));
    label6->setAutoFillBackground(true);
    label6->setPalette(*label_palette6);
    QLabel* label6_2 = new QLabel();
    label6_2->setText("无响应");
    QHBoxLayout* layout_hlayout6 = new QHBoxLayout();
    layout_hlayout6->addWidget(label6);
    layout_hlayout6->addWidget(label6_2);
    layout_vping1->addLayout(layout_hlayout6);

    QLabel* label11 = new QLabel();
    label11->setMaximumWidth(20);
    label11->setMinimumWidth(20);
    QPalette* label_palette11 = new QPalette();
    label_palette11->setColor(QPalette::Background, QColor(225, 127, 127));
    label11->setAutoFillBackground(true);
    label11->setPalette(*label_palette11);
    QLabel* label11_2 = new QLabel();
    label11_2->setText("丢包率异常");
    QHBoxLayout* layout_hlayout11 = new QHBoxLayout();
    layout_hlayout11->addWidget(label11);
    layout_hlayout11->addWidget(label11_2);
    layout_vping1->addLayout(layout_hlayout11);
    layout_vping1->addStretch(1);

    QHBoxLayout* layout_hlayout7 = new QHBoxLayout();
    QLabel* label7 = new QLabel();
    label_alivecount = new QLabel();
    label7->setText("存活节点数：");
    label7->setMinimumWidth(80);
    label_alivecount->setText("");
    layout_hlayout7->addWidget(label7);
    layout_hlayout7->addWidget(label_alivecount);

    QHBoxLayout* layout_hlayout8 = new QHBoxLayout();
    QLabel* label8 = new QLabel();
    label_alivecountA = new QLabel();
    label8->setText("A网节点数：");
    label8->setMinimumWidth(80);
    label_alivecountA->setText("");
    layout_hlayout8->addWidget(label8);
    layout_hlayout8->addWidget(label_alivecountA);

    QHBoxLayout* layout_hlayout9 = new QHBoxLayout();
    QLabel* label9 = new QLabel();
    label_alivecountB = new QLabel();
    label9->setText("B网节点数：");
    label9->setMinimumWidth(80);
    label_alivecountB->setText("");
    layout_hlayout9->addWidget(label9);
    layout_hlayout9->addWidget(label_alivecountB);

    QHBoxLayout* layout_hlayout10 = new QHBoxLayout();
    QLabel* label10 = new QLabel();
    label_alivecountC = new QLabel();
    label10->setText("信息网节点数：");
    label10->setMinimumWidth(80);
    label_alivecountC->setText("");
    layout_hlayout10->addWidget(label10);
    layout_hlayout10->addWidget(label_alivecountC);

    layout_vping1->addLayout(layout_hlayout7);
    layout_vping1->addLayout(layout_hlayout8);
    layout_vping1->addLayout(layout_hlayout9);
    layout_vping1->addLayout(layout_hlayout10);

    layout_vping1->addStretch(1);

    pingProgressBar=new QProgressBar();
    pingProgressBar->setMaximumWidth(200);
    pingProgressBar->setMaximum(100);
    pingProgressBar->setValue(0);
    pingProgressBar->setTextVisible(true);
    layout_vping1->addWidget(pingProgressBar);

    layout_vping1->addStretch(6);

    button_pingHidden = new QPushButton("隐藏无响应节点");
    button_ping = new QPushButton("开始Ping检测");
    button_ping_save = new QPushButton("导出");
    button_ping_save->setEnabled(false);
    layout_vping1->addWidget(button_pingHidden);
    layout_vping1->addWidget(button_ping);
    layout_vping1->addWidget(button_ping_save);

    QHBoxLayout* layout_hlayout = new QHBoxLayout();

    layout_hlayout->addWidget(table_ping_list);
    layout_hlayout->addLayout(layout_vping1);
    layout_ping->addLayout(layout_hlayout);


    QWidget * widget_ping = new QWidget();
    widget_ping->setLayout(layout_ping);

    tabWidgets->addTab(widget_ping, "存活检测");

}

void MainWindow::drawGather(){
    QVBoxLayout* layout_vgather = new QVBoxLayout();
    layout_vgather->setAlignment(Qt::AlignTop);
    layout_vgather->setMargin(30);




    QCheckBox* checkbox_a = new QCheckBox("上位机系统信息");
    checkbox_a->setTristate(true);
    layout_vgather->addWidget(checkbox_a);

    checkbox_gather_sys_map.insert("checkSysAll",checkbox_a);

    checkbox_gather_sys_map.insert("arp",new QCheckBox("ARP表"));
    checkbox_gather_sys_map.insert("route",new QCheckBox("路由信息"));
    checkbox_gather_sys_map.insert("netcard",new QCheckBox("网卡属性"));
    checkbox_gather_sys_map.insert("firewall",new QCheckBox("防火墙规则"));
    checkbox_gather_sys_map.insert("process",new QCheckBox("当前进程信息"));
    checkbox_gather_sys_map.insert("dcom",new QCheckBox("DCOM配置"));
    checkbox_gather_sys_map.insert("service",new QCheckBox("系统服务信息"));
    checkbox_gather_sys_map.insert("kb",new QCheckBox("补丁情况"));
    checkbox_gather_sys_map.insert("systeminfo",new QCheckBox("系统信息"));
    checkbox_gather_sys_map.insert("regedit",new QCheckBox("注册表信息"));
    checkbox_gather_sys_map.insert("soft",new QCheckBox("已安装软件"));
    checkbox_gather_sys_map.insert("event",new QCheckBox("系统日志"));
    checkbox_gather_sys_map.insert("port",new QCheckBox("端口情况"));
    checkbox_gather_sys_map.insert("account",new QCheckBox("系统账号信息"));
    checkbox_gather_sys_map.insert("dns",new QCheckBox("DNS缓存"));
    checkbox_gather_sys_map.insert("schtasks",new QCheckBox("计划任务"));
    checkbox_gather_sys_map.insert("smb",new QCheckBox("文件共享"));
    checkbox_gather_sys_map.insert("startup",new QCheckBox("启动项"));
    checkbox_gather_sys_map.insert("gpedit",new QCheckBox("组策略"));


    QCheckBox* checkbox_z=new QCheckBox("其他信息");
    checkbox_gather_sys_map.insert("other",checkbox_z);

    QGridLayout* layout_sys_gather = new QGridLayout();
    layout_sys_gather->setMargin(30);
    layout_sys_gather->setAlignment(Qt::AlignTop);

    QMap<QString,QCheckBox*>::iterator iter;
    int index=0;
    for (iter = checkbox_gather_sys_map.begin(); iter != checkbox_gather_sys_map.end();)
    {

        if((iter.value()!=checkbox_a) && (iter.value()!=checkbox_z)){
            layout_sys_gather->addWidget(iter.value(),index/CHECKBOX_COL_NUM,index%CHECKBOX_COL_NUM);
            index++;
        }
        iter++;
    }
    layout_sys_gather->addWidget(checkbox_z,index/CHECKBOX_COL_NUM,index%CHECKBOX_COL_NUM);

    layout_vgather->addLayout(layout_sys_gather);

    //--------------------700-----------------------

    QCheckBox* checkbox_b = new QCheckBox("700控制系统信息");
    checkbox_b->setTristate(true);
    layout_vgather->addWidget(checkbox_b);

    checkbox_gather_700_map.insert("check700All",checkbox_b);

    QGridLayout* layout_700_gather = new QGridLayout();
    layout_700_gather->setMargin(30);
    layout_700_gather->setAlignment(Qt::AlignTop);

    checkbox_gather_700_map.insert("ics_project",new QCheckBox("组态工程文件"));
    checkbox_gather_700_map.insert("ics_vf",new QCheckBox("VF配置和日志"));
    checkbox_gather_700_map.insert("ics_timesync",new QCheckBox("时钟同步日志"));
    checkbox_gather_700_map.insert("ics_dcs",new QCheckBox("控制器版本(发送SCNET指令)"));

    index=0;
    for (iter = checkbox_gather_700_map.begin(); iter != checkbox_gather_700_map.end();)
    {
        if(iter.value()!=checkbox_b){
            layout_700_gather->addWidget(iter.value(),index/CHECKBOX_COL_NUM,index%CHECKBOX_COL_NUM);
            index++;
        }
        iter++;
    }
    layout_vgather->addLayout(layout_700_gather);

    //-----------------900-------------------

    QCheckBox* checkbox_c = new QCheckBox("900控制系统信息");
    checkbox_c->setTristate(true);
    layout_vgather->addWidget(checkbox_c);
    checkbox_gather_900_map.insert("check900All",checkbox_c);

    QGridLayout* layout_900_gather = new QGridLayout();
    layout_900_gather->setMargin(30);
    layout_900_gather->setAlignment(Qt::AlignTop);

    checkbox_gather_900_map.insert("900_project",new QCheckBox("SafeContrix组态工程文件(手选)"));
    checkbox_gather_900_map.insert("900_timesync",new QCheckBox("时钟同步日志"));
    checkbox_gather_900_map.insert("900_scada",new QCheckBox("SCADA"));

    index=0;
    for (iter = checkbox_gather_900_map.begin(); iter != checkbox_gather_900_map.end();)
    {
        if(iter.value()!=checkbox_c){
            layout_900_gather->addWidget(iter.value(),index/CHECKBOX_COL_NUM,index%CHECKBOX_COL_NUM);
            index++;
        }
        iter++;
    }
    layout_vgather->addLayout(layout_900_gather);

    //---------------------------------

    layout_vgather->addStretch(1);
    button_gather= new QPushButton("一键收集");
    layout_vgather->addWidget(button_gather);

    QWidget* widget_gather = new QWidget();
    widget_gather->setLayout(layout_vgather);
    tabWidgets->addTab(widget_gather, "信息收集");
}

#ifdef ENABLE_DCOM
void MainWindow::drawDCOM(){
    QVBoxLayout* layout_dcom_vlayout = new QVBoxLayout();
    layout_dcom_vlayout->setMargin(30);
    layout_dcom_vlayout->setAlignment(Qt::AlignTop);
    QTabWidget* dcomTabWidgets = new QTabWidget();

    table_dcom_result = new QTableWidget();
    table_dcom_result->setColumnCount(1);
    table_dcom_result->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_dcom_result->verticalHeader()->setVisible(false);
    table_dcom_result->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_dcom_result->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_dcom_result->setHorizontalHeaderLabels(QStringList() << tr("检测结果"));
    table_dcom_result->setColumnWidth(0,600);
    QVBoxLayout* layout_result = new QVBoxLayout();
    layout_result->addWidget(table_dcom_result);

    QWidget* widget_result = new QWidget();
    widget_result->setLayout(layout_result);
    dcomTabWidgets->addTab(widget_result, "检测结果");

    layout_dcom_vlayout->addWidget(dcomTabWidgets);

    table_dcom_access = new QTableWidget();
    table_dcom_access->setColumnCount(5);
    table_dcom_access->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_dcom_access->verticalHeader()->setVisible(false);
    table_dcom_access->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_dcom_access->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_dcom_access->setHorizontalHeaderLabels(QStringList() << tr("本地帐户/用户组")<< tr("本地访问限制")<< tr("远程访问限制")<< tr("默认本地访问")<< tr("默认远程访问"));
    table_dcom_access->setColumnWidth(0,256);
    QVBoxLayout* layout_access = new QVBoxLayout();
    layout_access->addWidget(table_dcom_access);
    QWidget* widget_access = new QWidget();
    widget_access->setLayout(layout_access);
    dcomTabWidgets->addTab(widget_access, "访问权限");

    table_dcom_lanuchActive = new QTableWidget();
    table_dcom_lanuchActive->setColumnCount(9);
    table_dcom_lanuchActive->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_dcom_lanuchActive->verticalHeader()->setVisible(false);
    table_dcom_lanuchActive->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_dcom_lanuchActive->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_dcom_lanuchActive->setHorizontalHeaderLabels(QStringList()
                <<tr("本地帐户/用户组")
                <<tr("本地启动限制")
                <<tr("远程启动限制")
                <<tr("本地激活限制")
                <<tr("远程激活限制")
                <<tr("默认本地启动")
                <<tr("默认远程启动")
                <<tr("默认本地激活")
                <<tr("默认远程激活"));
    table_dcom_lanuchActive->setColumnWidth(0,256);

    QVBoxLayout* layout_lanuchActive = new QVBoxLayout();
    layout_lanuchActive->addWidget(table_dcom_lanuchActive);
    QWidget* widget_lanuchActive = new QWidget();
    widget_lanuchActive->setLayout(layout_lanuchActive);
    dcomTabWidgets->addTab(widget_lanuchActive, "启动和激活权限");

    table_dcom_opc = new QTableWidget();
    table_dcom_opc->setColumnCount(8);
    table_dcom_opc->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_dcom_opc->verticalHeader()->setVisible(false);
    table_dcom_opc->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_dcom_opc->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_dcom_opc->setHorizontalHeaderLabels(QStringList()
                <<tr("OPCServer")
                <<tr("本地帐户/用户组")
                <<tr("本地访问")
                <<tr("远程访问")
                <<tr("本地启动")
                <<tr("远程启动")
                <<tr("本地激活")
                <<tr("远程激活"));
    table_dcom_opc->setColumnWidth(0,256);
    table_dcom_opc->setColumnWidth(1,256);
    QVBoxLayout* layout_dcom_opc = new QVBoxLayout();
    layout_dcom_opc->addWidget(table_dcom_opc);
    QWidget* widget_OPC = new QWidget();
    widget_OPC->setLayout(layout_dcom_opc);
    dcomTabWidgets->addTab(widget_OPC, "OPC组件");

    table_dcom_authorization = new QTableWidget();
    table_dcom_authorization->setColumnCount(2);
    table_dcom_authorization->setColumnWidth(0,300);
    table_dcom_authorization->setColumnWidth(1,300);
    table_dcom_authorization->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_dcom_authorization->verticalHeader()->setVisible(false);
    table_dcom_authorization->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_dcom_authorization->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_dcom_authorization->setHorizontalHeaderLabels(QStringList()
                                                        <<tr("策略")
                                                        <<tr("安全设置"));

    QFont textFont = QFont("consolas", 10, QFont::Light);
    QStringList array = QStringList()<<tr("从网络访问此计算机")
                <<tr("拒绝从网络访问这台计算机")
                <<tr("网络访问: 本地帐户的共享和安全模型")
                <<tr("网络访问: 将 Everyone 权限应用于匿名用户");
    for(int i=0;i<array.size();i++){
        table_dcom_authorization->insertRow(i);
        QTableWidgetItem *item = new QTableWidgetItem(array[i]);
        item->setFont(textFont);
        table_dcom_authorization->setItem(i,0,item);
        item = new QTableWidgetItem();
        item->setFont(textFont);
        table_dcom_authorization->setItem(i,1,item);
    }




    QVBoxLayout* layout_dcom_authorization = new QVBoxLayout();
    layout_dcom_authorization->addWidget(table_dcom_authorization);

    QWidget* widget_authorization = new QWidget();
    widget_authorization->setLayout(layout_dcom_authorization);
    dcomTabWidgets->addTab(widget_authorization, "用户权限分配");




    QHBoxLayout* layout_hlayout = new QHBoxLayout();
    button_DCOM_recommend=new QPushButton("推荐设置");
    layout_hlayout->addWidget(button_DCOM_recommend);

    button_DCOM_refresh=new QPushButton("刷新");
    layout_hlayout->addWidget(button_DCOM_refresh);

    button_DCOM_apply=new QPushButton("应用");
    layout_hlayout->addWidget(button_DCOM_apply);

    layout_dcom_vlayout->addLayout(layout_hlayout);


    QWidget *widget_dcom = new QWidget();
    widget_dcom->setLayout(layout_dcom_vlayout);
    tabWidgets->addTab(widget_dcom, "DCOM配置");

}
#endif

void MainWindow::drawPerformance(){
    checkbox_perform_dir.append(new QCheckBox("CPU占用"));
    checkbox_perform_dir.append(new QCheckBox("可用内存"));
    checkbox_perform_dir.append(new QCheckBox("硬盘读占用率"));
    checkbox_perform_dir.append(new QCheckBox("硬盘写占用率"));

    QString netcardName=myperformanceclass->getPhyNetCardNames();
    int netcardNum=myperformanceclass->getPhyNetCardNum();

    QStringList tmp =netcardName.split(',');

    for(int i=0;i<tmp.size() && i<netcardNum;i++){
        checkbox_perform_dir.append(new QCheckBox("网卡" +QString::number(i+1)+":"+ QString(tmp[i])));
    }


    QGridLayout* layout_gperformance=new QGridLayout();
    for(int i=0;i<checkbox_perform_dir.size();i++){
        layout_gperformance->addWidget(checkbox_perform_dir[i],i%4,i/4);
    }

    QVBoxLayout* layout_vperformance = new QVBoxLayout();
    layout_vperformance->setAlignment(Qt::AlignTop);
    layout_vperformance->addLayout(layout_gperformance);

    mychartclass=new mychart(netcardName,netcardNum);

    layout_vperformance->addWidget(mychartclass->chartView);

    QHBoxLayout *layout_hlayout = new QHBoxLayout();

    button_performance=new QPushButton("开始监视");

    button_performance_save=new QPushButton();
    button_performance_save->setText("保存");

    layout_hlayout->addWidget(button_performance);
    layout_hlayout->addWidget(button_performance_save);
    layout_vperformance->addLayout(layout_hlayout);
    widget_performance = new QWidget();
    widget_performance->setLayout(layout_vperformance);

    tabWidgets->addTab(widget_performance, "性能监视");

}

void MainWindow::drawWireshark(){
    QHBoxLayout* layout_wireshark_hlayout = new QHBoxLayout();
    layout_wireshark_hlayout->setMargin(30);
    layout_wireshark_hlayout->setAlignment(Qt::AlignLeft);

    QVBoxLayout* layout_vleft_layout = new QVBoxLayout();
    QHBoxLayout* layout_h_layout = new QHBoxLayout();
    QLabel* label = new QLabel();
    label->setText("ARP表");
    button_arp_refresh = new QPushButton("更新");
    layout_h_layout->addWidget(label);
    layout_h_layout->addWidget(button_arp_refresh);
    layout_h_layout->addStretch(1);

    layout_vleft_layout->addLayout(layout_h_layout);

    table_arp = new QTableWidget();
    table_arp->setColumnCount(2);
    table_arp->setColumnWidth(0,150);
    table_arp->setColumnWidth(1,150);

    table_arp->setSortingEnabled(false);
    table_arp->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_arp->verticalHeader()->setVisible(false);

    table_arp->setSelectionBehavior(QAbstractItemView::SelectRows);

    table_arp->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_arp->setHorizontalHeaderLabels(QStringList()<<"IP地址"<<"MAC地址");
    layout_vleft_layout->addWidget(table_arp);


    label = new QLabel();
    label->setText("日志信息");
    layout_vleft_layout->addWidget(label);


    table_log = new QTableWidget();
    table_log->setColumnCount(3);

    table_log->setSortingEnabled(false);
    table_log->horizontalHeader()->setDefaultSectionSize(CELL_SIZE);
//    table_log->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table_log->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_log->horizontalHeader()->setStretchLastSection(true);
//    table_log->horizontalHeader()->setVisible(false);

    table_log->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_log->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_log->setHorizontalHeaderLabels(QStringList()<<"时间"<<"类型"<<"事件");
    layout_vleft_layout->addWidget(table_log);

    label = new QLabel();
    label->setText("控制器网络诊断");
    layout_vleft_layout->addWidget(label);
    table_wireshark = new QTableWidget();
    table_wireshark->setColumnCount(15);
//    table_wireshark->setColumnWidth(0,150);

    table_wireshark->setSortingEnabled(false);
    table_wireshark->horizontalHeader()->setDefaultSectionSize(CELL_SIZE);
//    table_wireshark->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table_wireshark->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
//    table_wireshark->horizontalHeader()->setStretchLastSection(true);
//    table_wireshark->horizontalHeader()->setVisible(false);

    table_wireshark->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_wireshark->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_wireshark->setHorizontalHeaderLabels(QStringList()<<"IP"<<"类型"<<"网络接口状态"<<"网口连接状态"<<"网络连接速度"<<"网络工作模式"<<"负荷过重报警"<<"网络异常节点报警"<<"总线交错报警"<<"IP节点冲突报警"<<"SNTP故障报警"<<"工作备用标致"<<"应发包"<<"已收包"<<"丢包率");
    layout_vleft_layout->addWidget(table_wireshark);


    layout_wireshark_hlayout->addLayout(layout_vleft_layout);

    QVBoxLayout* layout_vright_layout = new QVBoxLayout();

    layout_vright_layout->setMargin(10);

    label = new QLabel();
    label->setText("网卡");

    layout_vright_layout->addWidget(label);
    layout_vright_layout->addStretch(1);

    QVBoxLayout* layout_v_netcard=new QVBoxLayout();

    mywireshark* tmpwireshark =new mywireshark();

    QStringList cardnames = tmpwireshark->getNetcards();

    for(int i=0;i<cardnames.length();i++){
        QStringList tmp = cardnames[i].split("\t");
        if(tmp.length()==3){
            QCheckBox * tmpCheck=new QCheckBox(tmp[0]);
            tmpCheck->setMaximumWidth(300);
            tmpCheck->setStatusTip(tmp[1]);
            tmpCheck->setToolTip(tmp[2]);
            checkbox_netcard.append(tmpCheck);
            layout_v_netcard->addWidget(tmpCheck);
        }
    }
    layout_vright_layout->addLayout(layout_v_netcard);
    layout_vright_layout->addStretch(1);

    delete tmpwireshark;

    QVBoxLayout* layout_vlayout = new QVBoxLayout();

    layout_vlayout = new QVBoxLayout();
    QHBoxLayout* layout_hlayout = new QHBoxLayout();
    label_count_gb = new QLabel();
    label_count_gb->setText("0");
    label = new QLabel();
    label->setText("广播包数");
    label->setMinimumWidth(100);
    layout_hlayout->addWidget(label);
    layout_hlayout->addWidget(label_count_gb);
    layout_vlayout->addLayout(layout_hlayout);

    layout_hlayout = new QHBoxLayout();
    label_count_zb = new QLabel();
    label_count_zb->setText("0");
    label = new QLabel();
    label->setText("组播包数");
    label->setMinimumWidth(100);
    layout_hlayout->addWidget(label);
    layout_hlayout->addWidget(label_count_zb);
    layout_vlayout->addLayout(layout_hlayout);

    layout_hlayout = new QHBoxLayout();
    label_count_db = new QLabel();
    label_count_db->setText("0");
    label = new QLabel();
    label->setText("单播包数");
    label->setMinimumWidth(100);
    layout_hlayout->addWidget(label);
    layout_hlayout->addWidget(label_count_db);
    layout_vlayout->addLayout(layout_hlayout);

    layout_hlayout = new QHBoxLayout();
    label = new QLabel();
    label->setText("数据包统计");
    label->setMinimumWidth(160);
    layout_hlayout->addWidget(label);
    layout_hlayout->addLayout(layout_vlayout);

    layout_vright_layout->addLayout(layout_hlayout);
    layout_vright_layout->addStretch(2);

    label = new QLabel("抓包停止条件");
    combobox_stop = new QComboBox();
    combobox_stop->addItem("手动");
    combobox_stop->addItem("1小时后停止");
    combobox_stop->addItem("每张网卡抓满1000包后停止");
//    line_filter=new QLineEdit();
    layout_vright_layout->addWidget(label);
    layout_vright_layout->addWidget(combobox_stop);

    layout_vright_layout->addStretch(2);

    label = new QLabel("抓包过滤条件（语法同tcpdump）");
    combobox_filter = new QComboBox();
    combobox_filter->setEditable(true);
    combobox_filter->addItem("");
    combobox_filter->addItem("tcp");
    combobox_filter->addItem("udp");
    combobox_filter->addItem("ip");
//    line_filter=new QLineEdit();
    layout_vright_layout->addWidget(label);
    layout_vright_layout->addWidget(combobox_filter);

    layout_vright_layout->addStretch(4);
    button_wireshark= new QPushButton();
    button_wireshark->setText("开始抓包");
    button_log_save=new QPushButton();
    button_log_save->setText("日志保存");

    layout_vright_layout->addWidget(button_wireshark);
    layout_vright_layout->addWidget(button_log_save);


    layout_wireshark_hlayout->addLayout(layout_vright_layout);

    QWidget* widget_wireshark = new QWidget();
    widget_wireshark->setLayout(layout_wireshark_hlayout);
    tabWidgets->addTab(widget_wireshark, "网络监测");




}

void MainWindow::drawProcess(){

    table_process = new QTableWidget();

    table_process->setColumnCount(7);
    table_process->setColumnWidth(0,150);
    table_process->setColumnWidth(1,60);
    table_process->setColumnWidth(2,60);
    table_process->setColumnWidth(3,60);
    table_process->setColumnWidth(4,60);
    table_process->setColumnWidth(5,120);
//    table_process->setColumnWidth(6,300);


    table_process->setSortingEnabled(false);
    table_process->verticalHeader()->setDefaultSectionSize(CELL_SIZE);
    table_process->verticalHeader()->setVisible(false);
    table_process->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_process->setFrameShape(QFrame::NoFrame);
    table_process->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_process->setHorizontalHeaderLabels(QStringList() << tr("名称")<<tr("进程号")<<tr("父进程号")<<tr("会话")<<tr("线程数")<<tr("内存(KB)")<<tr("命令行"));
    table_process->horizontalHeader()->setStretchLastSection(true);
    connect(table_process->horizontalHeader(),&QHeaderView::sectionClicked,this,&MainWindow::processSort);

    QVBoxLayout * layout = new QVBoxLayout();
    layout->addWidget(table_process);

    process_save = new QPushButton("保存");
    layout->addWidget(process_save);

    QWidget* widget_process = new QWidget();
    widget_process->setLayout(layout);
    tabWidgets->addTab(widget_process, "进程查看");
}

void MainWindow::pingStart(){

    if(myglobal::pingActive==0){
        QList<int> targetList;
        QString ipRange = line_targetip->text().replace(" ","");
        if(ipRange.length()<=0)return;

        QRegExp rxlen("(\\d+)-(\\d+)");
        int pos=0;
        while ((pos = rxlen.indexIn(ipRange, pos)) >= 0) {
            if(rxlen.capturedTexts().size()>1){
                QString start=rxlen.capturedTexts()[1].trimmed();
                QString end=rxlen.capturedTexts()[2].trimmed();
                for(int i=start.toInt();i<=end.toInt();i++){
                    if(!targetList.contains(i))
                        targetList.append(i);
                }
            }
            pos += rxlen.matchedLength();
        }

        QRegExp rxlen1("(\\d+)");
        pos=0;
        while ((pos = rxlen1.indexIn(ipRange, pos)) >= 0) {
            if(rxlen1.capturedTexts().size()>1){
                QString ip=rxlen1.capturedTexts()[1].trimmed();
                if(!targetList.contains(ip.toInt()))
                    targetList.append(ip.toInt());
            }
            pos += rxlen1.matchedLength();
        }
        qSort(targetList);
        if(targetList.length()<=0){
            return;
        }
        if(!checkbox_A->isChecked() &&!checkbox_B->isChecked() &&!checkbox_C->isChecked() ){
            QMessageBox::warning(this,"错误",QString("至少选择一个网段"));
            return;
        }
        QRegExp rxlenIP("^((25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d)))\\.){2}(25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d)))$");
        QString ip_A=line_A->text().replace(" ","");
        QString ip_B=line_B->text().replace(" ","");
        QString ip_C=line_C->text().replace(" ","");
        if(checkbox_A->isChecked()){

            if(!rxlenIP.exactMatch(ip_A))
            {
                QMessageBox::warning(this,"错误",QString("控制网A地址不正确"));
                return;
            }
            myglobal::enable_A=true;

        }
        if(checkbox_B->isChecked()){
            if(!rxlenIP.exactMatch(ip_B))
            {
                QMessageBox::warning(this,"错误",QString("控制网B地址不正确"));
                return;
            }
            myglobal::enable_B=true;
        }
        if(checkbox_C->isChecked()){
            if(!rxlenIP.exactMatch(ip_C))
            {
                QMessageBox::warning(this,"错误",QString("信息网地址不正确"));
                return;
            }
            myglobal::enable_C=true;
        }

        checkbox_A->setEnabled(false);
        checkbox_B->setEnabled(false);
        checkbox_C->setEnabled(false);
        line_A->setEnabled(false);
        line_B->setEnabled(false);
        line_C->setEnabled(false);
        button_ping->setText("停止Ping");
        label_alivecount->setText("");
        label_alivecountA->setText("");
        label_alivecountB->setText("");
        label_alivecountC->setText("");
        myglobal::pingActive=1;
        myglobal::ip_A=ip_A;
        myglobal::ip_B=ip_B;
        myglobal::ip_C=ip_C;

        pingResultMutex.lock();
        pingDataModel->clear();
        pingData.clear();
        for(int i=0;i<targetList.length();i++){
            QPair<int,int[5*3]> tmp;
            tmp.first=targetList[i];
            tmp.second[2]=-1;//max=-1
            tmp.second[3]=65535;//min=65535
            tmp.second[5+2]=-1;//max=-1
            tmp.second[5+3]=65535;//min=65535
            tmp.second[5*2+2]=-1;//max=-1
            tmp.second[5*2+3]=65535;//min=65535
            pingData.append(tmp);

//            QList<QStandardItem*> items;
//            items.append(new QStandardItem(QString::number(targetList[i])));
//            items.append(new QStandardItem(""));
//            for(int j=0;j<15;j++){
//                items.append(new QStandardItem(""));
//            }
//            pingDataModel->appendRow(items);
        }

        pingResultMutex.unlock();

        pingTotal=0;
        pingCurrent=0;
        if(myglobal::enable_A)pingTotal+=targetList.length()*PINGCOUNT;
        if(myglobal::enable_B)pingTotal+=targetList.length()*PINGCOUNT;
        if(myglobal::enable_C)pingTotal+=targetList.length()*PINGCOUNT;
        pingProgressBar->setMaximum(pingTotal);
        pingProgressBar->setValue(0);

        myglobal::startTime = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");

        for(int i=0;i<targetList.length();i++){
            if(myglobal::enable_A){
                myping* a =new myping();
                connect(a,&myping::signal_pingResult,this,&MainWindow::pingResultUpdate);
                a->setNode(targetList[i],0);
                qThreadPool1->start(a);
            }
            if(myglobal::enable_B){
                myping* b =new myping();
                connect(b,&myping::signal_pingResult,this,&MainWindow::pingResultUpdate);
                b->setNode(targetList[i],1);
                qThreadPool2->start(b);
            }
            if(myglobal::enable_C){
                myping* c =new myping();
                connect(c,&myping::signal_pingResult,this,&MainWindow::pingResultUpdate);
                c->setNode(targetList[i],2);
                qThreadPool3->start(c);
            }
        }

    }else{
        myglobal::pingActive=0;

        checkbox_A->setEnabled(true);
        checkbox_B->setEnabled(true);
        checkbox_C->setEnabled(true);
        line_A->setEnabled(true);
        line_B->setEnabled(true);
        line_C->setEnabled(true);
        pingTotal=0;
        button_ping->setText("开始Ping检测");
        button_ping_save->setEnabled(true);
    }

}

void MainWindow::pingResultUpdate(int node,int netType ,int delay,int numOfSend,int numOfRecv){
    pingCurrent+=1;
    pingProgressBar->setValue(pingCurrent);
    pingResultMutex.lock();

    //更新发包收包最大最小总时延
    //然后计算存活节点总数
    int aliveA=0,aliveB=0,aliveC=0,alive=0;
    for(int i=0;i<pingData.length();i++){
        if(pingData[i].first==node){
            pingData[i].second[netType*5+0]=numOfSend;
            pingData[i].second[netType*5+1]=numOfRecv;
            if(delay!=-1){
                if(pingData[i].second[netType*5+2]<delay)pingData[i].second[netType*5+2]=delay;
                if(pingData[i].second[netType*5+3]>delay)pingData[i].second[netType*5+3]=delay;
                pingData[i].second[netType*5+4] += delay;
            }
        }

        if(pingData[i].second[1]>0)aliveA+=1;
        if(pingData[i].second[1+5]>0)aliveB+=1;
        if(pingData[i].second[1+5*2]>0)aliveC+=1;
        if(pingData[i].second[1]>0 || pingData[i].second[1+5]>0 || pingData[i].second[1+5*2]>0)alive+=1;

    }

    label_alivecount->setText(QString::number(alive));
    label_alivecountA->setText(QString::number(aliveA));
    label_alivecountB->setText(QString::number(aliveB));
    label_alivecountC->setText(QString::number(aliveC));

    int flag=1;//1:没在表格里显示

    for(int j=0;j<pingDataModel->rowCount();j++){
        if(pingDataModel->item(j,0)->text()==QString::number(node)){
            flag=0;
        }
    }

    if(flag){
        if(numOfRecv<=0 && hiddenOffPing==1){
            //不显示无响应节点
        }else{
            QList<QStandardItem*> items;
            items.append(new QStandardItem(QString::number(node)));
            items.append(new QStandardItem(""));
            for(int j=0;j<15;j++){
                items.append(new QStandardItem(""));
            }
            pingDataModel->appendRow(items);
        }
    }

    for(int j=0;j<pingDataModel->rowCount();j++){
        if(pingDataModel->item(j,0)->text()==QString::number(node)){
            flag=0;
            for(int i=0;i<pingData.length();i++){
                if(pingData[i].first==node){
                    //最大时延
                    if(pingData[i].second[netType*5+2]!=-1){
                        pingDataModel->item(j,netType*5+1)->setText(QString::number(pingData[i].second[netType*5+2]));
                    }else{
                        pingDataModel->item(j,netType*5+1)->setText("-");
                    }
                    //最小时延
                    if(pingData[i].second[netType*5+3]!=65535){
                        pingDataModel->item(j,netType*5+2)->setText(QString::number(pingData[i].second[netType*5+3]));
                    }else{
                        pingDataModel->item(j,netType*5+2)->setText("-");
                    }
                    //平均时延
                    if(pingData[i].second[netType*5+1]>0){
                        pingDataModel->item(j,netType*5+3)->setText(QString::number(pingData[i].second[netType*5+4]*1.0/pingData[i].second[netType*5+1],'f',2));
                    }else{
                        pingDataModel->item(j,netType*5+3)->setText("-");
                    }
                    //收包/发包
                    pingDataModel->item(j,netType*5+4)->setText(QString::number(pingData[i].second[netType*5+1])+"/"+QString::number(pingData[i].second[netType*5+0]));
                    //丢包率
                    if(pingData[i].second[netType*5+0]>0){
                        pingDataModel->item(j,netType*5+5)->setText(QString::number((pingData[i].second[netType*5+0]-pingData[i].second[netType*5+1])*100.0/pingData[i].second[netType*5+0],'f',2)+"%");
                    }else{
                        pingDataModel->item(j,netType*5+5)->setText("-");
                    }

                    break;
                }
            }
            break;
        }
    }

    pingUpdateColor();
    pingResultMutex.unlock();

    if(pingCurrent>=pingTotal){
        myglobal::pingActive=0;
        checkbox_A->setEnabled(true);
        checkbox_B->setEnabled(true);
        checkbox_C->setEnabled(true);
        line_A->setEnabled(true);
        line_B->setEnabled(true);
        line_C->setEnabled(true);
        pingTotal=0;
        button_ping->setText("开始Ping检测");
        button_ping_save->setEnabled(true);
    }

}

void MainWindow::pingUpdateColor(){

    for(int i=0;i<pingDataModel->rowCount();i++){
        for(int netType=0;netType<3;netType++){
            if(pingDataModel->item(i,netType*5+1+2)!=nullptr){
                if(pingDataModel->item(i,netType*5+1+2)->text()!=""){
                    if(pingDataModel->item(i,netType*5+1+2)->text()=="-"){
                        pingDataModel->item(i,netType*5+1+2)->setBackground(QColor(192, 192, 192));
                    }else{
                        double aveTime=pingDataModel->item(i,netType*5+1+2)->text().toDouble();
                        if(aveTime<50){
                            pingDataModel->item(i,netType*5+1+2)->setBackground(QColor(0, 255, 0));
                        }else if(aveTime<100){
                            pingDataModel->item(i,netType*5+1+2)->setBackground(QColor(255, 255, 0));
                        }else if(aveTime>100){
                            pingDataModel->item(i,netType*5+1+2)->setBackground(QColor(191, 205, 219));
                        }
                    }
                }
            }
            if(pingDataModel->item(i,netType*5+1+4)!=nullptr){
                if(pingDataModel->item(i,netType*5+1+4)->text()!=""){
                    if(pingDataModel->item(i,netType*5+1+4)->text()!="0.00%"
                            && pingDataModel->item(i,netType*5+1+4)->text()!="100.00%"){
                        pingDataModel->item(i,netType*5+1+4)->setBackground(QColor(225, 127, 127));
                    }
                }
            }
        }
    }
}

void MainWindow::pingHidden(){
    if(hiddenOffPing==0){
        hiddenOffPing=1;
        button_pingHidden->setText("显示无响应节点");
    }else{
        hiddenOffPing=0;
        button_pingHidden->setText("隐藏无响应节点");
    }
    pingUpdate();
}

void MainWindow::pingUpdate(){
    pingResultMutex.lock();
    pingDataModel->clear();

    for(int i=0;i<pingData.length();i++){

        if(pingData[i].second[1]<=0 && pingData[i].second[1+5]<=0 && pingData[i].second[1+5*2]<=0){
            if(hiddenOffPing==1){
                continue;
            }
        }

        QList<QStandardItem*> items;
        items.append(new QStandardItem(QString::number(pingData[i].first)));

        for(int netType=0;netType<3;netType++){
            if(netType==0 && myglobal::enable_A==false)continue;
            if(netType==1 && myglobal::enable_B==false)continue;
            if(netType==2 && myglobal::enable_C==false)continue;
            if(pingData[i].second[netType+0]==0){
                for(int j=0;j<5;j++){
                    items.append(new QStandardItem(""));
                }
            }else{
                //最大时延
                if(pingData[i].second[netType*5+2]!=-1){
                    items.append(new QStandardItem(QString::number(pingData[i].second[netType*5+2])));
                }else{
                    items.append(new QStandardItem("-"));
                }
                //最小时延
                if(pingData[i].second[netType*5+3]!=65535){
                    items.append(new QStandardItem(QString::number(pingData[i].second[netType*5+3])));
                }else{
                    items.append(new QStandardItem("-"));
                }
                //平均时延
                if(pingData[i].second[netType*5+1]>0){
                    items.append(new QStandardItem(QString::number(pingData[i].second[netType*5+4]*1.0/pingData[i].second[netType*5+1],'f',2)));
                }else{
                    items.append(new QStandardItem("-"));
                }
                //收包/发包
                items.append(new QStandardItem(QString::number(pingData[i].second[netType*5+1])+"/"+QString::number(pingData[i].second[netType*5+0])));
                //丢包率
                if(pingData[i].second[netType*5+0]>0){
                    items.append(new QStandardItem(QString::number((pingData[i].second[netType*5+0]-pingData[i].second[netType*5+1])*100.0/pingData[i].second[netType*5+0],'f',2)+"%"));
                }else{
                    items.append(new QStandardItem("-"));
                }
            }
        }

        pingDataModel->appendRow(items);
    }

    pingUpdateColor();
    pingResultMutex.unlock();
}

void MainWindow::pingSave(){

    if(configSelectLogDir()){
        QString path=myglobal::log_save_dir;
        QDir dir;
        dir.mkpath(path);
        QString fileName="/Ping";
        if(myglobal::enable_A){
            fileName+="_A_"+myglobal::ip_A;
        }
        if(myglobal::enable_B){
            fileName+="_B_"+myglobal::ip_B;
        }
        if(myglobal::enable_C){
            fileName+="_C_"+myglobal::ip_C;
        }
        fileName+="_"+myglobal::startTime;
        fileName+=".csv";

        QFile file(path+fileName);

        if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"错误",QString("打开文件")+file.fileName()+QString("失败"));
            return;
        }
        else
        {
            QTextStream textStream(&file);
            textStream<<QString(",");

            textStream<<QString("A网")<<QString(",,,,,,");
            textStream<<QString("B网")<<QString(",,,,,,");
            textStream<<QString("C网")<<QString(",,,,,,");

            textStream<<QString("\n节点,");

            textStream<<QString("发包,收包,最大时延,最小时延,平均时延,丢包率,");
            textStream<<QString("发包,收包,最大时延,最小时延,平均时延,丢包率,");
            textStream<<QString("发包,收包,最大时延,最小时延,平均时延,丢包率\n");

            for(int i=0;i<pingData.length();i++){
                textStream<<pingData[i].first<<",";
                for(int netType=0;netType<3;netType++){
                    textStream<<pingData[i].second[netType*5+0]<<",";
                    textStream<<pingData[i].second[netType*5+1]<<",";
                    if(pingData[i].second[netType*5+2]!=-1){
                        textStream<<pingData[i].second[netType*5+2]<<",";
                    }else{
                        textStream<<"-"<<",";
                    }
                    if(pingData[i].second[netType*5+3]!=65535){
                        textStream<<pingData[i].second[netType*5+3]<<",";
                    }else{
                        textStream<<"-"<<",";
                    }
                    if(pingData[i].second[netType*5+1]>0){
                        textStream<<QString::number(pingData[i].second[netType*5+4]*1.0/pingData[i].second[netType*5+1],'f',2)<<",";
                    }else{
                        textStream<<"-"<<",";
                    }

                    if(pingData[i].second[netType*5+0]>0){
                        textStream<<QString::number((pingData[i].second[netType*5+0]-pingData[i].second[netType*5+1])*100.0/pingData[i].second[netType*5+0],'f',2)<<"%"<<",";
                    }else{
                        textStream<<"-"<<",";
                    }
                }
                textStream<<"\n";
            }

            file.close();
            QMessageBox::information(this,"提示",QString("文件保存至")+file.fileName());
        }
    }
}

void MainWindow::checkboxSelectSysALL(int stat){
    if (stat==0){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_sys_map.begin(); iter != checkbox_gather_sys_map.end();++iter)
        {
            if(iter.key()=="checkSysAll")continue;
            iter.value()->setChecked(false);
        }
    }

    if (stat==2){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_sys_map.begin(); iter != checkbox_gather_sys_map.end();++iter)
        {
            if(iter.key()=="checkSysAll")continue;
            iter.value()->setChecked(true);
        }
    }
}

void MainWindow::checkboxSelect700ALL(int stat){
    if (stat==0){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_700_map.begin(); iter != checkbox_gather_700_map.end();++iter)
        {
            if(iter.key()=="check700All")continue;
            iter.value()->setChecked(false);
        }
    }

    if (stat==2){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_700_map.begin(); iter != checkbox_gather_700_map.end();++iter)
        {
            if(iter.key()=="check700All")continue;
            iter.value()->setChecked(true);
        }
    }
}

void MainWindow::checkboxSelect900ALL(int stat){
    if (stat==0){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_900_map.begin(); iter != checkbox_gather_900_map.end();++iter)
        {
            if(iter.key()=="check900All")continue;
            iter.value()->setChecked(false);
        }
    }

    if (stat==2){
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_900_map.begin(); iter != checkbox_gather_900_map.end();++iter)
        {
            if(iter.key()=="check700All")continue;
            iter.value()->setChecked(true);
        }
    }
}



void MainWindow::gatherStart(){

    if(configSelectInfoDir()){
        QStringList* checklist=new QStringList();
        QMap<QString,QCheckBox*>::iterator iter;

        for (iter = checkbox_gather_sys_map.begin(); iter != checkbox_gather_sys_map.end();++iter)
        {
            if(iter.key()=="checkSysAll")continue;
            if(iter.value()->isChecked()){
                checklist->append(iter.key());
            }

        }
        for (iter = checkbox_gather_700_map.begin(); iter != checkbox_gather_700_map.end();++iter)
        {
            if(iter.key()=="check700All")continue;
            if(iter.value()->isChecked()){
                checklist->append(iter.key());
            }

        }

        for (iter = checkbox_gather_900_map.begin(); iter != checkbox_gather_900_map.end();++iter)
        {
            if(iter.key()=="check900All")continue;

            if(iter.key()=="900_project" && iter.value()->isChecked()){
                if(!configSelect900ProjectDir()){
                    delete checklist;
                    checklist=nullptr;
                    return;
                }
            }
            if(iter.value()->isChecked()){
                checklist->append(iter.key());
            }
        }

        if(checklist->length()>0){
            infoGathed=0;
            button_gather->setEnabled(false);
            button_gather->setText(QString("正在收集信息"));

//            qDebug()<<info_save_dir;

            QString del_file = myglobal::info_save_dir;
            QDir dir;
            dir.setPath(del_file);
            dir.removeRecursively();

            if(checklist->contains("dcom")){
                if(DCOMPermission.count()==0)dcomRefresh();
                QString path=myglobal::info_save_dir+QString("/上位机系统信息/DCOM配置/");
                myunit::mkdir(path);
                QFile file(path+QString("DCOM权限.csv"));

                if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
                {

                }
                else
                {
                    QTextStream textStream(&file);
                    textStream<<QString("组或用户名,本地访问限制,远程访问限制,默认本地访问,默认远程访问,本地启动限制,远程启动限制,默认本地启动,默认远程启动,本地激活限制,远程激活限制,默认本地激活,默认远程激活\n");
                    QMap<QString,QMap<QString,QString>>::iterator iter2;
                    for (iter2 = DCOMPermission.begin(); iter2 != DCOMPermission.end();++iter2)
                    {
                        textStream<<iter2.key()<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalAccessRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteAccessRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalAccessDefault"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteAccessDefault"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalLanuchRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteLanuchRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalLanuchDefault"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteLanuchDefault"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalActiveRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteActiveRestriction"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["LocalActiveDefault"])<<",";
                        textStream<<getFriendlyStr(iter2.value()["RemoteActiveDefault"])<<"\n";
                    }

                    file.close();
                }
            }

            myinfoclass->setDirname(myglobal::info_save_dir,myglobal::info_zip_save_dir);
            myinfoclass->setList(checklist);
            myinfoclass->start();
        }else{
            delete checklist;
        }
    }
}

void MainWindow::gatherResultUpdate(QString tag){
    if(tag=="ok"){
        button_gather->setText("一键收集");
        button_gather->setEnabled(true);
    }else if(tag==QString("正在打包")){
        button_gather->setText(tag);
    }
    else{
        infoGathed+=1;
        button_gather->setText(tag+" 已收集"+QString::number(infoGathed)+"项，共"+QString::number(myinfoclass->checklist->length())+"项");
    }
}

int MainWindow::configSelectLogDir(){
    QFileDialog dialog(nullptr);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择日志保存路径");
    dialog.setDirectory(myglobal::log_save_dir);
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();
        myglobal::log_save_dir=dirname[0];
        return 1;
    }
    return 0;
}

int MainWindow::configSelectWiresharkDir(){
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择抓包保存路径");
    dialog.setDirectory(myglobal::wireshark_save_dir);
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();
        myglobal::wireshark_save_dir = dirname[0];
        return 1;
    }
    return 0;
}

int MainWindow::configSelectInfoDir(){
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择信息保存路径");
    dialog.setDirectory(myglobal::info_zip_save_dir);
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();
        myglobal::info_zip_save_dir = dirname[0];
        return 1;
    }
    return 0;
}

int MainWindow::configSelectProcessDir(){
    QFileDialog dialog(nullptr);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择进程信息保存路径");
    dialog.setDirectory(myglobal::process_save_dir);
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();
        myglobal::process_save_dir=dirname[0];
        return 1;
    }
    return 0;
}


void MainWindow::checkBoxPerformUpdate(int stat){
    for(int i=0;i<checkbox_perform_dir.length();i++){
        emit updateVisible(i,checkbox_perform_dir[i]->isChecked());
    }
}

void MainWindow::performanceStart(){
    if(myperformanceclass->getActive()==0){
        button_performance->setText("停止");
        myperformanceclass->start();

    }else{
        myperformanceclass->setActive(0);
        button_performance->setText("开始监视");
    }
}

void MainWindow::performanceSave(){
    if(configSelectLogDir()){
        QString path=myglobal::log_save_dir;
        myunit::mkdir(path);

        QPixmap p = QPixmap::grabWidget(widget_performance);
        QImage image=p.toImage();
        image.save(path+QString("/性能监视.png"));

        QFile file(path+QString("/性能监视.csv"));
        if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"错误",QString("打开文件")+file.fileName()+QString("失败"));
            return;
        }
        else
        {
            QTextStream textStream(&file);
            for(int i=0;i<mychartclass->data.length();i++){
                textStream<<mychartclass->dataName[i];
                textStream<<",";
                for(int j=0;j<mychartclass->data[i]->length();j++){
                    textStream<<(*mychartclass->data[i])[j];
                    textStream<<",";
                }
                textStream<<"\n";
            }

            file.close();
            QMessageBox::information(this,"提示",QString("文件保存至")+file.fileName());
        }
    }
}

void MainWindow::dcomRefresh(){

    #ifdef ENABLE_DCOM
    table_dcom_access->clearContents();
    table_dcom_access->setRowCount(0);
    table_dcom_lanuchActive->clearContents();
    table_dcom_lanuchActive->setRowCount(0);
    table_dcom_opc->clearContents();
    table_dcom_opc->setRowCount(0);
    table_dcom_result->clearContents();
    table_dcom_result->setRowCount(0);
    #endif

    DCOMPermission.clear();

    QRegExp rxlen("([A|D]);;(\\w+);;;([\\w-]+)");

    //解析访问限制
    QString MachineAccessRestriction = mydcomclass->getMachineAccessRestriction();

    int pos=0;
    while ((pos = rxlen.indexIn(MachineAccessRestriction, pos)) > 0) {
        if(rxlen.capturedTexts().length()==4){
            QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());
            if(name=="")name=rxlen.cap(3);
            if(!DCOMPermission.contains(name)){
                QMap<QString,QString> tmp;
                tmp.insert("name",name);
                tmp.insert("sid",rxlen.cap(3));
                tmp.insert("LocalAccessRestriction","0");
                tmp.insert("RemoteAccessRestriction","0");
                tmp.insert("LocalAccessDefault","0");
                tmp.insert("RemoteAccessDefault","0");
                tmp.insert("LocalLanuchRestriction","0");
                tmp.insert("RemoteLanuchRestriction","0");
                tmp.insert("LocalLanuchDefault","0");
                tmp.insert("RemoteLanuchDefault","0");
                tmp.insert("LocalActiveRestriction","0");
                tmp.insert("RemoteActiveRestriction","0");
                tmp.insert("LocalActiveDefault","0");
                tmp.insert("RemoteActiveDefault","0");
                DCOMPermission.insert(name,tmp);
            }

            if(rxlen.cap(1)=="A"){
                if(rxlen.cap(2).contains("DC")){
                    if(DCOMPermission[name]["LocalAccessRestriction"]!="2"){
                        DCOMPermission[name]["LocalAccessRestriction"]="1";
                    }
                }
                if(rxlen.cap(2).contains("LC")){
                    if(DCOMPermission[name]["RemoteAccessRestriction"]!="2"){
                        DCOMPermission[name]["RemoteAccessRestriction"]="1";
                    }
                }
            }

            if(rxlen.cap(1)=="D"){
                if(rxlen.cap(2).contains("DC")){
                    DCOMPermission[name]["LocalAccessRestriction"]="2";
                }
                if(rxlen.cap(2).contains("LC")){
                    DCOMPermission[name]["RemoteAccessRestriction"]="2";
                }
            }
        }

        pos += rxlen.matchedLength();
    }

    //解析激活限制
    QString MachineLaunchRestriction = mydcomclass->getMachineLaunchRestriction();
    pos=0;
    while ((pos = rxlen.indexIn(MachineLaunchRestriction, pos)) > 0) {
        if(rxlen.capturedTexts().length()==4){
            QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());
            if(name=="")name=rxlen.cap(3);
            if(!DCOMPermission.contains(name)){
                QMap<QString,QString> tmp;
                tmp.insert("name",name);
                tmp.insert("sid",rxlen.cap(3));
                tmp.insert("LocalAccessRestriction","0");
                tmp.insert("RemoteAccessRestriction","0");
                tmp.insert("LocalAccessDefault","0");
                tmp.insert("RemoteAccessDefault","0");
                tmp.insert("LocalLanuchRestriction","0");
                tmp.insert("RemoteLanuchRestriction","0");
                tmp.insert("LocalLanuchDefault","0");
                tmp.insert("RemoteLanuchDefault","0");
                tmp.insert("LocalActiveRestriction","0");
                tmp.insert("RemoteActiveRestriction","0");
                tmp.insert("LocalActiveDefault","0");
                tmp.insert("RemoteActiveDefault","0");
                DCOMPermission.insert(name,tmp);
            }

            if(rxlen.cap(1)=="A"){
                if(rxlen.cap(2).contains("DC")){
                    if(DCOMPermission[name]["LocalLanuchRestriction"]!="2"){
                        DCOMPermission[name]["LocalLanuchRestriction"]="1";
                    }
                }
                if(rxlen.cap(2).contains("LC")){
                    if(DCOMPermission[name]["RemoteLanuchRestriction"]!="2"){
                        DCOMPermission[name]["RemoteLanuchRestriction"]="1";
                    }
                }
                if(rxlen.cap(2).contains("SW")){
                    if(DCOMPermission[name]["LocalActiveRestriction"]!="2"){
                        DCOMPermission[name]["LocalActiveRestriction"]="1";
                    }
                }
                if(rxlen.cap(2).contains("RP")){
                    if(DCOMPermission[name]["RemoteActiveRestriction"]!="2"){
                        DCOMPermission[name]["RemoteActiveRestriction"]="1";
                    }
                }
            }

            if(rxlen.cap(1)=="D"){
                if(rxlen.cap(2).contains("DC")){
                    DCOMPermission[name]["LocalLanuchRestriction"]="2";
                }
                if(rxlen.cap(2).contains("LC")){
                    DCOMPermission[name]["RemoteLanuchRestriction"]="2";
                }
                if(rxlen.cap(2).contains("SW")){
                    DCOMPermission[name]["LocalActiveRestriction"]="2";
                }
                if(rxlen.cap(2).contains("RP")){
                    DCOMPermission[name]["RemoteActiveRestriction"]="2";
                }
            }
        }

        pos += rxlen.matchedLength();
    }

    //解析默认访问权限
    QString DefaultAccessPermission = mydcomclass->getDefaultAccessPermission();
    pos=0;
    while ((pos = rxlen.indexIn(DefaultAccessPermission, pos)) > 0) {
        if(rxlen.capturedTexts().length()==4){
            QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());
            if(name=="")name=rxlen.cap(3);
            if(!DCOMPermission.contains(name)){
                QMap<QString,QString> tmp;
                tmp.insert("name",name);
                tmp.insert("sid",rxlen.cap(3));
                tmp.insert("LocalAccessRestriction","0");
                tmp.insert("RemoteAccessRestriction","0");
                tmp.insert("LocalAccessDefault","0");
                tmp.insert("RemoteAccessDefault","0");
                tmp.insert("LocalLanuchRestriction","0");
                tmp.insert("RemoteLanuchRestriction","0");
                tmp.insert("LocalLanuchDefault","0");
                tmp.insert("RemoteLanuchDefault","0");
                tmp.insert("LocalActiveRestriction","0");
                tmp.insert("RemoteActiveRestriction","0");
                tmp.insert("LocalActiveDefault","0");
                tmp.insert("RemoteActiveDefault","0");
                DCOMPermission.insert(name,tmp);
            }

            if(rxlen.cap(1)=="A"){
                if(rxlen.cap(2).contains("DC")){
                    if(DCOMPermission[name]["LocalAccessDefault"]!="2"){
                        DCOMPermission[name]["LocalAccessDefault"]="1";
                    }
                }
                if(rxlen.cap(2).contains("LC")){
                    if(DCOMPermission[name]["RemoteAccessDefault"]!="2"){
                        DCOMPermission[name]["RemoteAccessDefault"]="1";
                    }
                }
            }

            if(rxlen.cap(1)=="D"){
                if(rxlen.cap(2).contains("DC")){
                    DCOMPermission[name]["LocalAccessDefault"]="2";
                }
                if(rxlen.cap(2).contains("LC")){
                    DCOMPermission[name]["RemoteAccessDefault"]="2";
                }
            }
        }

        pos += rxlen.matchedLength();
    }

    //解析默认激活限制
    QString DefaultLaunchPermission = mydcomclass->getDefaultLaunchPermission();
    pos=0;
    while ((pos = rxlen.indexIn(DefaultLaunchPermission, pos)) > 0) {
        if(rxlen.capturedTexts().length()==4){
            QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());
            if(name=="")name=rxlen.cap(3);
            if(!DCOMPermission.contains(name)){
                QMap<QString,QString> tmp;
                tmp.insert("name",name);
                tmp.insert("sid",rxlen.cap(3));
                tmp.insert("LocalAccessRestriction","0");
                tmp.insert("RemoteAccessRestriction","0");
                tmp.insert("LocalAccessDefault","0");
                tmp.insert("RemoteAccessDefault","0");
                tmp.insert("LocalLanuchRestriction","0");
                tmp.insert("RemoteLanuchRestriction","0");
                tmp.insert("LocalLanuchDefault","0");
                tmp.insert("RemoteLanuchDefault","0");
                tmp.insert("LocalActiveRestriction","0");
                tmp.insert("RemoteActiveRestriction","0");
                tmp.insert("LocalActiveDefault","0");
                tmp.insert("RemoteActiveDefault","0");
                DCOMPermission.insert(name,tmp);
            }

            if(rxlen.cap(1)=="A"){
                if(rxlen.cap(2).contains("DC")){
                    if(DCOMPermission[name]["LocalLanuchDefault"]!="2"){
                        DCOMPermission[name]["LocalLanuchDefault"]="1";
                    }
                }
                if(rxlen.cap(2).contains("LC")){
                    if(DCOMPermission[name]["RemoteLanuchDefault"]!="2"){
                        DCOMPermission[name]["RemoteLanuchDefault"]="1";
                    }
                }
                if(rxlen.cap(2).contains("SW")){
                    if(DCOMPermission[name]["LocalActiveDefault"]!="2"){
                        DCOMPermission[name]["LocalActiveDefault"]="1";
                    }
                }
                if(rxlen.cap(2).contains("RP")){
                    if(DCOMPermission[name]["RemoteActiveDefault"]!="2"){
                        DCOMPermission[name]["RemoteActiveDefault"]="1";
                    }
                }
            }

            if(rxlen.cap(1)=="D"){
                if(rxlen.cap(2).contains("DC")){
                    DCOMPermission[name]["LocalLanuchDefault"]="2";
                }
                if(rxlen.cap(2).contains("LC")){
                    DCOMPermission[name]["RemoteLanuchDefault"]="2";
                }
                if(rxlen.cap(2).contains("SW")){
                    DCOMPermission[name]["LocalActiveDefault"]="2";
                }
                if(rxlen.cap(2).contains("RP")){
                    DCOMPermission[name]["RemoteActiveDefault"]="2";
                }
            }
        }

        pos += rxlen.matchedLength();
    }

#ifdef ENABLE_DCOM
    QMap<QString,QMap<QString,QString>>::iterator iter;
    //展示访问权限
    for (iter = DCOMPermission.begin(); iter != DCOMPermission.end();++iter)
    {
        if(
                iter.value()["LocalAccessRestriction"]=="0" &&
                iter.value()["RemoteAccessRestriction"]=="0" &&
                iter.value()["LocalAccessDefault"]=="0" &&
                iter.value()["RemoteAccessDefault"]=="0"
                )
            continue;
        int num = table_dcom_access->rowCount();
        table_dcom_access->insertRow(num);
        table_dcom_access->setItem(num,0,new QTableWidgetItem(iter.value()["name"]));

        QStringList tmp;
        tmp << "LocalAccessRestriction" << "RemoteAccessRestriction" << "LocalAccessDefault" << "RemoteAccessDefault" ;
        for(int i=0;i<tmp.length();i++){
            QComboBox* comboBox1 = new QComboBox();
            comboBox1->addItem("","");
            comboBox1->addItem("允许","允许");
            comboBox1->addItem("拒绝","拒绝");
            comboBox1->setCurrentIndex(iter.value()[tmp[i]].toInt());
            table_dcom_access->setCellWidget(num,i+1,comboBox1);
        }
    }

    //展示激活权限
    for (iter = DCOMPermission.begin(); iter != DCOMPermission.end();++iter)
    {
        if(
                iter.value()["LocalLanuchRestriction"]=="0" &&
                iter.value()["RemoteLanuchRestriction"]=="0" &&
                iter.value()["LocalActiveRestriction"]=="0" &&
                iter.value()["RemoteActiveRestriction"]=="0" &&
                iter.value()["LocalLanuchDefault"]=="0" &&
                iter.value()["RemoteLanuchDefault"]=="0" &&
                iter.value()["LocalActiveDefault"]=="0" &&
                iter.value()["RemoteActiveDefault"]=="0"
                )
            continue;
        int num = table_dcom_lanuchActive->rowCount();
        table_dcom_lanuchActive->insertRow(num);
        table_dcom_lanuchActive->setItem(num,0,new QTableWidgetItem(iter.value()["name"]));
        QStringList tmp;
        tmp << "LocalLanuchRestriction" << "RemoteLanuchRestriction" << "LocalActiveRestriction" << "RemoteActiveRestriction" << "LocalLanuchDefault" << "RemoteLanuchDefault" << "LocalActiveDefault" << "RemoteActiveDefault";
        for(int i=0;i<tmp.length();i++){
            QComboBox* comboBox1 = new QComboBox();
            comboBox1->addItem("","");
            comboBox1->addItem("允许","允许");
            comboBox1->addItem("拒绝","拒绝");
            comboBox1->setCurrentIndex(iter.value()[tmp[i]].toInt());
            table_dcom_lanuchActive->setCellWidget(num,i+1,comboBox1);
        }

    }
#endif
    OpcPermission.clear();
    OpcInfo.clear();

    QMap<QString,QString> tmpQMap1;
    tmpQMap1.insert("uuid","{41EBD53D-36C4-4027-B2B4-09A6E4A362DD}");
    tmpQMap1.insert("name","SUPCON.SCRTCore");
    OpcInfo.append(tmpQMap1);
    QMap<QString,QString> tmpQMap2;
    tmpQMap2.insert("uuid","{13486D44-4821-11D2-A494-3CB306C10000}");
    tmpQMap2.insert("name","OpcEnum");
    OpcInfo.append(tmpQMap2);

//    QMap<QString,QString> tmpQMap3;
//    tmpQMap3.insert("uuid","{03837503-098b-11d8-9414-505054503030}");
//    tmpQMap3.insert("name","test");
//    OpcInfo.append(tmpQMap3);

    for(int i=0;i<OpcInfo.length();i++){
        OpcInfo[i].insert("isexists","true");
        OpcInfo[i].insert("accessDefault","false");
        OpcInfo[i].insert("launchDefault","false");

        QMap<QString,QMap<QString,QString>>tmp;
        OpcPermission.append(tmp);
    }


//    QList<QMap<QString,QMap<QString,QString>>> OpcPermission;
//    OpcInfo.clear();

    //获取OPC权限
    for(int i=0;i<OpcInfo.length();i++){
        QString uuid=OpcInfo[i]["uuid"];
        QString opcname=OpcInfo[i]["name"];

        QString opcAccess = mydcomclass->getOPCAccess(uuid.toStdString().c_str());
        pos=0;
        if(opcAccess=="default"){
            OpcInfo[i]["accessDefault"]="true";
        }else if(opcAccess=="notexist"){
            OpcInfo[i]["isexists"]="false";
        }else{
            while ((pos = rxlen.indexIn(opcAccess, pos)) > 0) {
                pos += rxlen.matchedLength();
                if(rxlen.capturedTexts().length()==4){
                    QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());

                    if(!OpcPermission[i].contains(name)){
                        QMap<QString,QString>tmp;
                        tmp.insert("LocalAccess","0");
                        tmp.insert("RemoteAccess","0");
                        tmp.insert("LocalLaunch","0");
                        tmp.insert("RemoteLaunch","0");
                        tmp.insert("LocalActive","0");
                        tmp.insert("RemoteActive","0");
                        OpcPermission[i].insert(name,tmp);
                    }



                    if(rxlen.cap(1)=="A"){
                        if(rxlen.cap(2).contains("DC")){
                            if(OpcPermission[i][name]["LocalAccess"]!="2"){
                                OpcPermission[i][name]["LocalAccess"]="1";
                            }
                        }
                        if(rxlen.cap(2).contains("LC")){
                            if(OpcPermission[i][name]["RemoteAccess"]!="2"){
                                OpcPermission[i][name]["RemoteAccess"]="1";
                            }
                        }
                    }
                    if(rxlen.cap(1)=="D"){
                        if(rxlen.cap(2).contains("DC")){
                            OpcPermission[i][name]["LocalAccess"]="2";
                        }
                        if(rxlen.cap(2).contains("LC")){
                            OpcPermission[i][name]["RemoteAccess"]="2";
                        }
                    }

                 }
            }
        }


        QString opcLaunch = mydcomclass->getOPCLaunch(uuid.toStdString().c_str());
        pos=0;
        if(opcLaunch=="default"){
            OpcInfo[i]["launchDefault"]="true";
        }else if(opcLaunch=="notexist"){
            OpcInfo[i]["isexists"]="false";
        }else{
            while ((pos = rxlen.indexIn(opcLaunch, pos)) > 0) {
                pos += rxlen.matchedLength();
                if(rxlen.capturedTexts().length()==4){
                    QString name = mydcomclass->getUsernameBySID(rxlen.cap(3).toStdString().c_str());

                    if(!OpcPermission[i].contains(name)){
                        QMap<QString,QString>tmp;
                        tmp.insert("LocalAccess","0");
                        tmp.insert("RemoteAccess","0");
                        tmp.insert("LocalLaunch","0");
                        tmp.insert("RemoteLaunch","0");
                        tmp.insert("LocalActive","0");
                        tmp.insert("RemoteActive","0");
                        OpcPermission[i].insert(name,tmp);
                    }



                    if(rxlen.cap(1)=="A"){
                        if(rxlen.cap(2).contains("DC")){
                            if(OpcPermission[i][name]["LocalLaunch"]!="2"){
                                OpcPermission[i][name]["LocalLaunch"]="1";
                            }
                        }
                        if(rxlen.cap(2).contains("LC")){
                            if(OpcPermission[i][name]["RemoteLaunch"]!="2"){
                                OpcPermission[i][name]["RemoteLaunch"]="1";
                            }
                        }
                        if(rxlen.cap(2).contains("SW")){
                            if(OpcPermission[i][name]["LocalActive"]!="2"){
                                OpcPermission[i][name]["LocalActive"]="1";
                            }
                        }
                        if(rxlen.cap(2).contains("RP")){
                            if(OpcPermission[i][name]["RemoteActive"]!="2"){
                                OpcPermission[i][name]["RemoteActive"]="1";
                            }
                        }
                    }
                    if(rxlen.cap(1)=="D"){
                        if(rxlen.cap(2).contains("DC")){
                            OpcPermission[i][name]["LocalLaunch"]="1";
                        }
                        if(rxlen.cap(2).contains("LC")){
                            OpcPermission[i][name]["RemoteLaunch"]="1";
                        }
                        if(rxlen.cap(2).contains("SW")){
                            OpcPermission[i][name]["LocalActive"]="1";
                        }
                        if(rxlen.cap(2).contains("RP")){
                            OpcPermission[i][name]["RemoteActive"]="1";
                        }
                    }

                 }
            }
        }

    }

#ifdef ENABLE_DCOM
    //展示OPC权限
    for(int i=0;i<OpcInfo.length();i++){
        if(OpcInfo[i]["isexists"]=="false"){
            int num =table_dcom_opc->rowCount();
            table_dcom_opc->insertRow(num);

            table_dcom_opc->setItem(num,0,new QTableWidgetItem(OpcInfo[i]["name"]));
            for(int j=0;j<8;j++){
                table_dcom_opc->setItem(num,j+1,new QTableWidgetItem("不存在"));
            }
        }

        if(OpcInfo[i]["accessDefault"]=="true" && OpcInfo[i]["launchDefault"]=="true"){
            int num =table_dcom_opc->rowCount();
            table_dcom_opc->insertRow(num);

            table_dcom_opc->setItem(num,0,new QTableWidgetItem(OpcInfo[i]["name"]));
            for(int j=0;j<8;j++){
                table_dcom_opc->setItem(num,j+1,new QTableWidgetItem("默认"));
            }
        }

        for (iter = OpcPermission[i].begin(); iter != OpcPermission[i].end();++iter){
            int num =table_dcom_opc->rowCount();
            table_dcom_opc->insertRow(num);

            table_dcom_opc->setItem(num,0,new QTableWidgetItem(OpcInfo[i]["name"]));
            table_dcom_opc->setItem(num,1,new QTableWidgetItem(iter.key()));
            if(OpcInfo[i]["accessDefault"]=="true"){
                table_dcom_opc->setItem(num,2,new QTableWidgetItem("默认"));
                table_dcom_opc->setItem(num,3,new QTableWidgetItem("默认"));
            }else{
                table_dcom_opc->setItem(num,2,new QTableWidgetItem(getFriendlyStr(iter.value()["LocalAccess"])));
                table_dcom_opc->setItem(num,3,new QTableWidgetItem(getFriendlyStr(iter.value()["RemoteAccess"])));
            }

            if(OpcInfo[i]["launchDefault"]=="true"){
                table_dcom_opc->setItem(num,4,new QTableWidgetItem("默认"));
                table_dcom_opc->setItem(num,5,new QTableWidgetItem("默认"));
                table_dcom_opc->setItem(num,6,new QTableWidgetItem("默认"));
                table_dcom_opc->setItem(num,7,new QTableWidgetItem("默认"));
            }else{
                table_dcom_opc->setItem(num,4,new QTableWidgetItem(getFriendlyStr(iter.value()["LocalLaunch"])));
                table_dcom_opc->setItem(num,5,new QTableWidgetItem(getFriendlyStr(iter.value()["RemoteLaunch"])));
                table_dcom_opc->setItem(num,6,new QTableWidgetItem(getFriendlyStr(iter.value()["LocalActive"])));
                table_dcom_opc->setItem(num,7,new QTableWidgetItem(getFriendlyStr(iter.value()["RemoteActive"])));
            }

        }


    }
#endif

#ifdef ENABLE_DCOM
    getSecedit();
    dcomCheck();
#endif
}

QString MainWindow::getFriendlyStr(QString value){
    if(value=="0")return QString("--");
    if(value=="1")return QString("允许");
    if(value=="2")return QString("拒绝");
    return QString("");
}

#ifdef ENABLE_DCOM
void MainWindow::dcomApply(){
    if(!IsUserAnAdmin()){
        QMessageBox::warning(this,"提示",QString("请使用管理员权限登录！"));
        return;
    }



    QString accessRestriction("O:BAG:BAD:");
    QString accessDefault("O:BAG:BAD:");

    QString launchAndActiveRestriction("O:BAG:BAD:");
    QString launchAndActiveDefault("O:BAG:BAD:");

    int num= table_dcom_access->rowCount();
    if(num==0)return;
    for(int i=0;i<num;i++){
        QString username = table_dcom_access->item(i,0)->text();
        QString sid = mydcomclass->getSIDByUsername(username.toStdString().c_str());
        QString APermission("CC");
        QString DPermission("CC");

        int tmp=((QComboBox*)(table_dcom_access->cellWidget(i,1)))->currentIndex();
        if(tmp==1){
            APermission += "DC";
        }
        else if( tmp == 2){
            DPermission += "DC";
        }

        tmp=((QComboBox*)(table_dcom_access->cellWidget(i,2)))->currentIndex();

        if (tmp == 1){
            APermission+="LC";
        }
        else if (tmp == 2){
            DPermission+="LC";
        }

        if(APermission!="CC"){
            accessRestriction+="(A;;"+APermission+";;;"+sid+")";
        }
        if(DPermission!="CC"){
            accessRestriction+="(D;;"+DPermission+";;;"+sid+")";
        }


        APermission="CC";
        DPermission="CC";
        tmp=((QComboBox*)(table_dcom_access->cellWidget(i,3)))->currentIndex();
        if (tmp == 1){
            APermission+="DC";
        }
        else if(tmp == 2){
            DPermission+="DC";
        }

        tmp=((QComboBox*)(table_dcom_access->cellWidget(i,4)))->currentIndex();
        if(tmp == 1){
            APermission+="LC";
        }
        else if (tmp == 2){
            DPermission+="LC";
        }

        if(APermission!=QString("CC")){
            accessDefault+="(A;;"+APermission+";;;"+sid+")";
        }
        if(DPermission!=QString("CC")){
            accessDefault+="(D;;"+DPermission+";;;"+sid+")";
        }
    }

    num= table_dcom_lanuchActive->rowCount();
    if(num==0)return;
    for(int i=0;i<num;i++){
        QString username = table_dcom_lanuchActive->item(i,0)->text();
        QString sid = mydcomclass->getSIDByUsername(username.toStdString().c_str());
        QString APermission("CC");

        QString DPermission=("CC");
        int tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,1)))->currentIndex();
        if(tmp == 1){
            APermission+="DC";
        }
        else if(tmp == 2){
            DPermission+="DC";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,2)))->currentIndex();
        if(tmp == 1){
            APermission+="LC";
        }
        else if(tmp == 2){
            DPermission+="LC";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,3)))->currentIndex();
        if(tmp == 1){
            APermission+="SW";
        }
        else if(tmp == 2){
            DPermission+="SW";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,4)))->currentIndex();
        if(tmp == 1){
            APermission+="RP";
        }
        else if(tmp == 2){
            DPermission+="RP";
        }
        if(APermission!="CC"){
            launchAndActiveRestriction+="(A;;"+APermission+";;;"+sid+")";
        }
        if(DPermission!="CC"){
            launchAndActiveRestriction+="(D;;"+DPermission+";;;"+sid+")";
        }

        APermission="CC";

        DPermission="CC";
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,5)))->currentIndex();
        if(tmp == 1){
            APermission+="DC";
        }
        else if(tmp == 2){
            DPermission+="DC";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,6)))->currentIndex();
        if(tmp == 1){
            APermission+="LC";
        }
        else if(tmp == 2){
            DPermission+="LC";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,7)))->currentIndex();
        if(tmp == 1){
            APermission+="SW";
        }
        else if(tmp == 2){
            DPermission+="SW";
        }
        tmp=((QComboBox*)(table_dcom_lanuchActive->cellWidget(i,8)))->currentIndex();
        if(tmp == 1){
            APermission+="RP";
        }
        else if(tmp == 2){
            DPermission+="RP";
        }

        if(APermission!=QString("CC")){
            launchAndActiveDefault+="(A;;"+APermission+";;;"+sid+")";
        }
        if(DPermission!=QString("CC")){
            launchAndActiveDefault+="(D;;"+DPermission+";;;"+sid+")";
        }
    }
//       qDebug()<<"accessRestriction"<< accessRestriction;
//       qDebug()<<"accessDefault"<< accessDefault;
//       qDebug()<<"launchAndActiveRestriction"<< launchAndActiveRestriction;
//       qDebug()<<"launchAndActiveDefault"<< launchAndActiveDefault;

    mydcomclass->setMachineAccessRestriction(accessRestriction.toStdString().c_str());
    mydcomclass->setDefaultAccessPermission(accessDefault.toStdString().c_str());
    mydcomclass->setMachineLaunchRestriction(launchAndActiveRestriction.toStdString().c_str());
    mydcomclass->setDefaultLaunchPermission(launchAndActiveDefault.toStdString().c_str());
    dcomRefresh();
}






void MainWindow::dcomRecommend(){
    if(!IsUserAnAdmin()){
        QMessageBox::warning(this,"提示",QString("请使用管理员权限登录！"));
        return;
    }

    QString myusername = mydcomclass->getUserName();

    QString text("DCOM设置如下：\n");
    text+="修改DCOM权限，并增加Distributed COM Users组\n";
    text+="Distributed COM Users组添加当前用户:" + myusername+"\n";
    text+="OPC组件权限设为:默认\n";
    text+="\n组策略设置如下：\n";
    text+="从网络访问此计算机:Administrators、Backup Operators、Distributed COM Users、Everyone、Users\n";
    text+="拒绝从网络访问此计算机:Guest";
    text+="设置共享和安全模型为：经典\n";
    text+="设置Everyone权限应用于匿名用户为：禁用\n";

    QMessageBox msg(this);

    msg.setWindowTitle("提示");
    msg.setText(text);
    msg.setIcon(QMessageBox::Information);
    msg.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);

    if( msg.exec() == QMessageBox::Ok )
    {
        button_DCOM_recommend->setEnabled(false);
        myrecommendclass->start();
    }

}

void MainWindow::recommendFinish(QString tag){
    if(tag=="ok"){
        button_DCOM_recommend->setText("推荐设置");
        button_DCOM_recommend->setEnabled(true);
        dcomRefresh();
    }else{
        button_DCOM_recommend->setText(tag);
    }
}

void MainWindow::getSecedit(){
    if(IsUserAnAdmin()){

        myinfoclass->setDirname(info_save_dir,info_zip_save_dir);
        myinfoclass->saveSecedit();

        QFile file(info_save_dir+"/secedit/LOCALPOLICY.log");
        if(file.open(QIODevice::ReadOnly))
        {
            QTextStream _txt_stream(&file);
            _txt_stream.setCodec("UTF-16LE");
            QString result = _txt_stream.readAll();
            QRegExp rxlen("ForceGuest=(\\d+),(\\d+)");
            if(rxlen.indexIn(result)){
                if(rxlen.cap(2)=="0"){
                    table_dcom_authorization->item(2,1)->setText("经典 - 对本地用户进行身份验证，不改变其本来身份");
                }else if(rxlen.cap(2)=="1"){
                    table_dcom_authorization->item(2,1)->setText("仅来宾 - 对本地用户进行身份验证，其身份为来宾");
                }

            }

            QRegExp rxlen2("EveryoneIncludesAnonymous=(\\d+),(\\d+)");
            if(rxlen2.indexIn(result)){
                if(rxlen2.cap(2)=="0"){
                    table_dcom_authorization->item(3,1)->setText("已禁用");
                }else if(rxlen2.cap(2)=="1"){
                    table_dcom_authorization->item(3,1)->setText("已启用");
                }
            }

            QRegExp rxlen3("SeNetworkLogonRight\\s=\\s(.*)[\r|\n|$]");
            rxlen3.setMinimal(true);
            if(rxlen3.indexIn(result)){
                QString names("");
                QStringList tmp = rxlen3.capturedTexts()[1].split(',');
                for(int i=0;i<tmp.length();i++){
                    QString eachname=tmp[i].trimmed();
                    if(eachname.length()>1){
                        QString name;
                        if(eachname[0]=='*'){
                            eachname=eachname.mid(1);
                            name = mydcomclass->getUsernameBySID(eachname.toStdString().c_str());
                        }else{
                            name=eachname;
                        }


                        if(name.length()>1){
                            if(names!="")names=names+","+name;
                            else names=name;
                        }

                    }
                }

                table_dcom_authorization->item(0,1)->setText(names);

            }

            QRegExp rxlen4("SeDenyNetworkLogonRight\\s=\\s(.*)[\r|\n|$]");
            rxlen4.setMinimal(true);
            if(rxlen4.indexIn(result)){
                QString names("");
                QStringList tmp = rxlen4.capturedTexts()[1].split(',');

                for(int i=0;i<tmp.length();i++){
                    QString eachname=tmp[i].trimmed();
                    if(eachname.length()>1){
                        QString name;
                        if(eachname[0]=='*'){
                            eachname=eachname.mid(1);
                            name = mydcomclass->getUsernameBySID(eachname.toStdString().c_str());
                        }else{
                            name=eachname;
                        }

                        if(name.length()>1){
                            if(names!="")names=names+","+name;
                            else names=name;
                        }
                    }
                }

                table_dcom_authorization->item(1,1)->setText(names);

            }
        }
    }
    else addResult("未获得组策略信息，结果可能存在偏差");
}

void MainWindow::dcomCheck(){
    int onlyGuest=0;
    int everyoneIncludeAnonymous=0;
    int isdeny=0,isAllow=0;

    if(table_dcom_authorization->item(2,1)->text().contains("仅来宾")){
        onlyGuest=1;
    }
    if(table_dcom_authorization->item(3,1)->text().contains("已启用")){
        everyoneIncludeAnonymous=1;
    }
    QString username,groupname;
    if(onlyGuest){
        username="Guest";
    }else{
        username=mydcomclass->getUserName();
    }
    groupname=QString::fromWCharArray(mydcomclass->getGroupName(username.toStdWString().c_str()));

    if(table_dcom_authorization->item(2,1)->text().length()>0){
        QStringList denys = table_dcom_authorization->item(1,1)->text().split(',');
        for(int i=0;i<denys.length();i++){
            if(isInGroup(username,groupname,denys[i],everyoneIncludeAnonymous))isdeny=1;
        }

        if(isdeny)addResult(QString("用户：")+username+QString("没有从网络访问的权限"));

        QStringList allows = table_dcom_authorization->item(0,1)->text().split(',');
        for(int i=0;i<allows.length();i++){
            if(isInGroup(username,groupname,allows[i],everyoneIncludeAnonymous))isAllow=1;
        }
        if(!isAllow)addResult(QString("用户：")+username+QString("不允许从网络访问"));
    }

    int LocalAccessRestriction=0;
    int RemoteAccessRestriction=0;
    int LocalAccessDefault=0;
    int RemoteAccessDefault=0;
    int LocalLanuchRestriction=0;
    int RemoteLanuchRestriction=0;
    int LocalLanuchDefault=0;
    int RemoteLanuchDefault=0;
    int LocalActiveRestriction=0;
    int RemoteActiveRestriction=0;
    int LocalActiveDefault=0;
    int RemoteActiveDefault=0;

    QMap<QString,QMap<QString,QString>>::iterator iter;
    for (iter = DCOMPermission.begin(); iter != DCOMPermission.end();++iter)
    {
        if(isInGroup(username,groupname,iter.key(),everyoneIncludeAnonymous)){
            LocalAccessRestriction=judgePermission(LocalAccessRestriction,iter.value()["LocalAccessRestriction"]);
            RemoteAccessRestriction=judgePermission(RemoteAccessRestriction,iter.value()["RemoteAccessRestriction"]);
            LocalAccessDefault=judgePermission(LocalAccessDefault,iter.value()["LocalAccessDefault"]);
            RemoteAccessDefault=judgePermission(RemoteAccessDefault,iter.value()["RemoteAccessDefault"]);
            LocalLanuchRestriction=judgePermission(LocalLanuchRestriction,iter.value()["LocalLanuchRestriction"]);
            RemoteLanuchRestriction=judgePermission(RemoteLanuchRestriction,iter.value()["RemoteLanuchRestriction"]);
            LocalLanuchDefault=judgePermission(LocalLanuchDefault,iter.value()["LocalLanuchDefault"]);
            RemoteLanuchDefault=judgePermission(RemoteLanuchDefault,iter.value()["RemoteLanuchDefault"]);
            LocalActiveRestriction=judgePermission(LocalActiveRestriction,iter.value()["LocalActiveRestriction"]);
            RemoteActiveRestriction=judgePermission(RemoteActiveRestriction,iter.value()["RemoteActiveRestriction"]);
            LocalActiveDefault=judgePermission(LocalActiveDefault,iter.value()["LocalActiveDefault"]);
            RemoteActiveDefault=judgePermission(RemoteActiveDefault,iter.value()["RemoteActiveDefault"]);
        }
    }

    if( judgePermission2(LocalAccessDefault,LocalAccessRestriction)!=1){
        addResult("用户："+username+",没有本地访问权限");
    }
    if( judgePermission2(RemoteAccessDefault,RemoteAccessRestriction)!=1){
        addResult("用户："+username+",没有远程访问权限");
    }
    if( judgePermission2(LocalLanuchDefault,LocalLanuchRestriction)!=1){
        addResult("用户："+username+",没有本地启动权限");
    }
    if( judgePermission2(RemoteLanuchDefault,RemoteLanuchRestriction)!=1){
        addResult("用户："+username+",没有远程启动权限");
    }
    if( judgePermission2(LocalActiveDefault,LocalActiveRestriction)!=1){
        addResult("用户："+username+",没有本地激活权限");
    }
    if( judgePermission2(RemoteActiveDefault,RemoteActiveRestriction)!=1){
        addResult("用户："+username+",没有远程激活权限");
    }

    for(int i=0;i<OpcInfo.length();i++){
        if(OpcInfo[i]["isexists"]=="true"){
            if(OpcInfo[i]["accessDefault"]=="false"){
                int LocalAccess=0;
                int RemoteAccess=0;
                for (iter = OpcPermission[i].begin(); iter != OpcPermission[i].end();++iter)
                {
                    if(isInGroup(username,groupname,iter.key(),everyoneIncludeAnonymous)){
                        LocalAccess=judgePermission(LocalAccess,iter.value()["LocalAccess"]);
                        RemoteAccess=judgePermission(RemoteAccess,iter.value()["RemoteAccess"]);
                    }
                }
                if(judgePermission2(LocalAccess,LocalAccessRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有本地访问权限");
                }
                if(judgePermission2(RemoteAccess,RemoteAccessRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有远程访问权限");
                }
            }

            if(OpcInfo[i]["launchDefault"]=="false"){
                int LocalLaunch=0;
                int RemoteLaunch=0;
                int LocalActive=0;
                int RemoteActive=0;

                for (iter = OpcPermission[i].begin(); iter != OpcPermission[i].end();++iter)
                {
                    if(isInGroup(username,groupname,iter.key(),everyoneIncludeAnonymous)){
                        LocalLaunch=judgePermission(LocalLaunch,iter.value()["LocalLaunch"]);
                        RemoteLaunch=judgePermission(RemoteLaunch,iter.value()["RemoteLaunch"]);
                        LocalActive=judgePermission(LocalActive,iter.value()["LocalActive"]);
                        RemoteActive=judgePermission(RemoteActive,iter.value()["RemoteActive"]);
                    }
                }
                if(judgePermission2(LocalLaunch,LocalLanuchRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有本地启动权限");
                }
                if(judgePermission2(RemoteLaunch,RemoteLanuchRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有远程启动权限");
                }
                if(judgePermission2(LocalActive,LocalActiveRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有本地激活权限");
                }
                if(judgePermission2(RemoteActive,RemoteActiveRestriction)!=1){
                    addResult("用户："+username+",对OPC组件："+OpcInfo[i]["name"]+",没有远程激活权限");
                }
            }
        }
    }

    if(table_dcom_result->rowCount()==0){
        addResult("用户："+username+"权限配置正常");
    }

}

void MainWindow::addResult(QString value){
    int num = table_dcom_result->rowCount();
    table_dcom_result->insertRow(num);
    table_dcom_result->setItem(num,0,new QTableWidgetItem(value));

}

int MainWindow::isInGroup(QString username,QString groupname,QString targetGroup,int everyoneIncludeAnonymous){
    if(username.toUpper()==targetGroup.toUpper())return 1;
    QStringList buildIn;
    buildIn<<"EVERYONE"<<"AUTHENTICATED USERS"<<"INTERACTIVE";
    if(username.toUpper()!="ANONYMOUS LOGON"){
        for(int i=0;i<buildIn.length();i++){
            if(buildIn[i]==targetGroup.toUpper())return 1;
        }
    }else{
        if(everyoneIncludeAnonymous){
            if(targetGroup.toUpper()=="EVERYONE")return 1;
        }
    }

    QStringList userGroups=groupname.split(',');
    for(int i=0;i<userGroups.length();i++){
        if(targetGroup.toUpper()==userGroups[i].toUpper())return 1;
    }
    return 0;
}

int MainWindow::judgePermission(int value1,QString value2){
    if(value1==2 || value2=="2")return 2;
    if(value1==1 || value2=="1")return 1;
    return 0;
}

int MainWindow::judgePermission2(int Default,int Restriction){
    if(Default==2 || Restriction==2)return 0;
    if(Restriction==0)return 0;
    return Default;

}
#endif
QString MainWindow::getRandomString(int length)
{
    qsrand(QDateTime::currentMSecsSinceEpoch());

    const char ch[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int size = strlen(ch);
    QString tmp="";
    for(int i=0;i<length;i++){
        tmp+=ch[rand()%size];
    }

    return tmp;
}

void MainWindow::wiresharkStart(){
    int active=0;

    for(int i=0;i<myglobal::mywiresharkclasslist.length();i++){
        if(myglobal::mywiresharkclasslist[i]->getActive()==1){
            active=1;
        }
    }

    if(active==0){
        if(configSelectWiresharkDir()){
            mywiresharkcheckclass->active=0;

            label_count_db->setText("0");
            label_count_gb->setText("0");
            label_count_zb->setText("0");


            for(int i=0;i<myglobal::mywiresharkclasslist.length();i++){
                delete myglobal::mywiresharkclasslist[i];
                myglobal::mywiresharkclasslist[i]=nullptr;
            }
            myglobal::mywiresharkclasslist.clear();

            for(int i=0;i<mynetchartlist.length();i++){
                mynetchartlist[i]->close();
                mynetchartlist[i]=nullptr;
            }
            mynetchartlist.clear();

            wiresharkUpdateARPFromSys();
            table_wireshark->clearContents();
            table_wireshark->setRowCount(0);

            QString path=myglobal::wireshark_save_dir;
            QDir dir;
            dir.mkpath(path);
            totalMulticast=totalUnicast=totalBoardcast=0;
            int count=0;

            for(int i=0;i<checkbox_netcard.length();i++){
                if(checkbox_netcard[i]->isChecked()){
                    count+=1;
                    mywireshark* tmpmywireshark=new mywireshark();
                    myglobal::mywiresharkclasslist.append(tmpmywireshark);
                    tmpmywireshark->setNetcard(checkbox_netcard[i]->statusTip());
                    tmpmywireshark->setNetcardDescript(checkbox_netcard[i]->text());
                    tmpmywireshark->setFilter(combobox_filter->lineEdit()->text());
                    tmpmywireshark->setStop(combobox_stop->currentIndex());

                    tmpmywireshark->setDirName(path);
                    tmpmywireshark->start();

                    connect(tmpmywireshark,&mywireshark::signal_net,this,&MainWindow::updateWiresharkDiag);
                    connect(tmpmywireshark,&mywireshark::signal_wireshark,this,&MainWindow::updateWiresharkInfo);
                    connect(tmpmywireshark,&mywireshark::signal_total,this,&MainWindow::wiresharkUpdateTotal);
                    connect(tmpmywireshark,&mywireshark::signal_checkMAC,this,&MainWindow::wiresharkCheckMAC);
                    addLog("抓包","开始抓包，网卡："+checkbox_netcard[i]->text()+"，抓包文件路径："+path);
                }
            }

            if(count==0)return;
            mywiresharkcheckclass->start();

            combobox_stop->setEnabled(false);
            combobox_filter->setEnabled(false);
            button_wireshark->setText("停止");
            for(int i=0;i<checkbox_netcard.length();i++){
                checkbox_netcard[i]->setEnabled(false);
            }
        }
    }else{
        button_wireshark->setEnabled(false);
        for(int i=0;i<myglobal::mywiresharkclasslist.length();i++){
            myglobal::mywiresharkclasslist[i]->setActive(0);
        }
    }
}

void MainWindow::wiresharkUpdateARPFromSys(int stat){
    if(stat==0)addLog("ARP","读取ARP表");
    table_arp->clearContents();
    table_arp->setRowCount(0);

    QProcess p(nullptr);
    p.start("cmd",QStringList()<<"/c"<<"arp"<<"-a");
    p.waitForStarted();
    p.waitForFinished(-1);
    QString result = p.readAllStandardOutput();
    QRegExp rxlen("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\s+(([a-fA-F0-9]{2}[-:]){5}[a-fA-F0-9]{2})");
    int pos=0;
    while ((pos = rxlen.indexIn(result, pos)) > 0 ) {
        if(rxlen.capturedTexts().size()>1){
            if(!isMulticast(rxlen.capturedTexts()[1])){
                if(rxlen.capturedTexts()[2].toUpper()!="FF-FF-FF-FF-FF-FF"){
                    int num=table_arp->rowCount();
                    table_arp->insertRow(num);
                    QTableWidgetItem* item1 = new QTableWidgetItem(rxlen.capturedTexts()[1]);
                    table_arp->setItem(num,0,item1);
                    QTableWidgetItem* item2 = new QTableWidgetItem(rxlen.capturedTexts()[2]);
                    table_arp->setItem(num,1,item2);

                }
            }
        }

        pos += rxlen.matchedLength();
    }
}

void MainWindow::addLog(QString typeinfo ,QString info,int last){
    int num= table_log->rowCount();
    if(last!=0){
        for(int i=num-last>0?num-last:0;i<num;i++){
            if(table_log->item(i,2)->text()==info)return;
        }
    }
    QString nowtime = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");

    table_log->insertRow(num);
    table_log->setItem(num,0,new QTableWidgetItem(nowtime));
    table_log->setItem(num,1,new QTableWidgetItem(typeinfo));
    table_log->setItem(num,2,new QTableWidgetItem(info));
    table_log->scrollToBottom();
}

int MainWindow::isMulticast(QString inputstr){
    QRegExp rxlen("(\\d{1,3}\\.){3}\\d{1,3}");
    if(rxlen.exactMatch(inputstr)){
        QString tmp = inputstr.split('.')[0];
        bool ok;
        int tmpint = tmp.toInt(&ok);
        if(ok){
            if(tmpint>=224 && tmpint<=239)return true;
        }
    }
    return false;
}

void MainWindow::updateWiresharkInfo(int level,QString tag){
    switch(level){
        case 0:addLog("错误",tag);break;
        case 1:addLog("抓包",tag);break;
        case 2:addLog("信息",tag);break;
        default:break;
    }

    if(level==0 || level==1){
        int active=0;
        for(int i=0;i<myglobal::mywiresharkclasslist.length();i++){
            if(myglobal::mywiresharkclasslist[i]->getActive()==1){
                active=1;
            }
        }
        if(active==0){
            for(int i=0;i<checkbox_netcard.length();i++){
                checkbox_netcard[i]->setEnabled(true);
            }
            combobox_stop->setEnabled(true);
            combobox_filter->setEnabled(true);
            button_wireshark->setEnabled(true);
            button_wireshark->setText("开始抓包");
        }
    }
}

void MainWindow::wiresharkUpdateTotal(int type){
    if( type==1){
        totalBoardcast+=1;
        label_count_gb->setText(QString::number(totalBoardcast));
    }
    else if( type==2){
        totalMulticast+=1;
        label_count_zb->setText(QString::number(totalMulticast));
    }
    else if( type==3){
        totalUnicast+=1;
        label_count_db->setText(QString::number(totalUnicast));
    }
}

void MainWindow::wiresharkUpdateARPFromPackets(QString ip,QString mac){
    int num= table_arp->rowCount();
    for(int i=0;i<num;i++){
        QString tmpIP = table_arp->item(i,0)->text();
        QString tmpMAC = table_arp->item(i,1)->text();
        if(tmpIP==ip && tmpMAC==mac)return;
        if(tmpIP==ip && tmpMAC!=mac){
            table_arp->item(i,1)->setText(mac);
            addLog("ARP",ip+"MAC地址从"+tmpMAC+"更新至"+mac);
            return;
        }
    }
    table_arp->insertRow(num);
    QTableWidgetItem* item = new QTableWidgetItem(ip);
    table_arp->setItem(num,0,item);

    QTableWidgetItem* item2 = new QTableWidgetItem(mac);
    table_arp->setItem(num,1,item2);

}

void MainWindow::wiresharkCheckMAC(QString ip,QString mac){
    int num= table_arp->rowCount();
    for(int i=0;i<num;i++){
        QString tmpIP = table_arp->item(i,0)->text();
        QString tmpMAC = table_arp->item(i,1)->text();
        if(tmpIP==ip && tmpMAC==mac)return;
        if(tmpIP==ip && tmpMAC!=mac){
            addLog("ARP","ARP表记录IP:"+tmpIP+"的MAC为:"+tmpMAC+",IP包中MAC为:"+mac,10);
            wiresharkUpdateARPFromSys(1);
            return;
        }
    }
}

void MainWindow::wiresharkLogSave(){
    if(configSelectLogDir()){
        QString path=myglobal::log_save_dir;
        QDir dir;
        dir.mkpath(path);
        QFile file(path+QString("/网络监测日志.csv"));

        if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"错误",QString("打开文件")+file.fileName()+QString("失败"));
            return;
        }
        else
        {
            QTextStream textStream1(&file);
            textStream1<<QString("时间,类型,事件\n");
            for(int i=0;i<table_log->rowCount();i++){
                textStream1<<table_log->item(i,0)->text();
                textStream1<<",";
                textStream1<<table_log->item(i,1)->text();
                textStream1<<",";
                textStream1<<table_log->item(i,2)->text();
                textStream1<<"\n";
            }
            file.close();
//            QMessageBox::information(this,"提示",QString("文件保存至")+file.fileName());
        }

        QFile file2(path+QString("/ARP表存档.csv"));
        if(!file2.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"错误",QString("打开文件")+file2.fileName()+QString("失败"));
            return;
        }
        else
        {
            QTextStream textStream2(&file2);
            textStream2<<QString("IP地址,MAC地址\n");
            for(int i=0;i<table_arp->rowCount();i++){
                textStream2<<table_arp->item(i,0)->text();
                textStream2<<",";
                textStream2<<table_arp->item(i,1)->text();
                textStream2<<"\n";
            }
            file2.close();
//            QMessageBox::information(this,"提示",QString("文件保存至")+file.fileName());
        }

        QFile file3(path+QString("/控制器网络诊断.csv"));
        if(!file3.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"错误",QString("打开文件")+file3.fileName()+QString("失败"));
            return;
        }
        else
        {
            QTextStream textStream3(&file3);

            textStream3<<QString("IP,类型,网络接口状态,网口连接状态,网络连接速度,网络工作模式,负荷过重报警,网络异常节点报警,总线交错报警,IP节点冲突报警,SNTP故障报警,工作备用标致,应发包,已收包,丢包率\n");

            for(int i=0;i<table_wireshark->rowCount();i++){
                textStream3<<table_wireshark->item(i,0)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,1)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,2)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,3)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,4)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,5)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,6)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,7)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,8)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,9)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,10)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,11)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,12)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,13)->text();
                textStream3<<",";
                textStream3<<table_wireshark->item(i,14)->text();
                textStream3<<"\n";
            }
            file3.close();
            QMessageBox::information(this,"提示",QString("文件保存至")+path);
        }

    }
}

void MainWindow::wiresharkDiag(QString srcip_type,long shouldReceived,long hasReceived){

    int num= table_wireshark->rowCount();

    auto tmplist = srcip_type.split("_");
    QString ip_src= tmplist[0];
    QString diagType = tmplist[1];


    for(int i=0;i<num;i++){
        if(table_wireshark->item(i,0)->text()==ip_src && table_wireshark->item(i,1)->text()==diagType){
            table_wireshark->item(i,12)->setText(QString::number(shouldReceived));
            table_wireshark->item(i,13)->setText(QString::number(hasReceived));
            table_wireshark->item(i,14)->setText(QString::number((1-hasReceived*1.0/shouldReceived)*100)+"%");
            table_wireshark->scrollToBottom();
            return;
        }
    }
}

void MainWindow::processUpdate(QList<QMap<QString,QString>> info){
    processResultMutex.lock();
    QStringList processLog;
    QList<QMap<QString,QString>>::iterator iter;

    for (iter = info.begin(); iter != info.end();++iter){
        int flag=1;
        int index=table_process->rowCount();
        for(int i=0;i<index;i++){
            if(table_process->item(i,1)->text()==iter->value("PID")){
                table_process->item(i,0)->setText(iter->value("Name"));
                table_process->item(i,2)->setText(iter->value("PPID"));

                table_process->item(i,3)->setText(iter->value("Session"));
//                if(iter->value("Session")=="0"&& iter->value("Name").startsWith("VF")){
//                    table_process->item(i,0)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,1)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,2)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,3)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,4)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,5)->setBackgroundColor(QColor(191, 205, 219));
//                    table_process->item(i,6)->setBackgroundColor(QColor(191, 205, 219));
//                }
                table_process->item(i,4)->setText(iter->value("Threads"));
                table_process->item(i,5)->setText(iter->value("Memory")=="0"?"-":iter->value("Memory"));
                table_process->item(i,6)->setText(iter->value("Cmd"));

                processLog.append(iter->value("PID"));


                flag=0;
            }
        }

        if(flag==1){
            if(iter->value("Session")=="0" && iter->value("Name").startsWith("VF")){
                index=0;
            }
            table_process->insertRow(index);
            table_process->setItem(index,0,new QTableWidgetItem);
            table_process->setItem(index,1,new QTableWidgetItem);
            table_process->setItem(index,2,new QTableWidgetItem);
            table_process->setItem(index,3,new QTableWidgetItem);
            table_process->setItem(index,4,new QTableWidgetItem);
            table_process->setItem(index,5,new QTableWidgetItem);
            table_process->setItem(index,6,new QTableWidgetItem);

            table_process->item(index,0)->setText(iter->value("Name"));
            table_process->item(index,1)->setText(iter->value("PID"));
            table_process->item(index,2)->setText(iter->value("Session"));
//            if(iter->value("Session")=="0" && iter->value("Name").startsWith("VF")){
//                table_process->item(index,0)->setBackgroundColor(QColor(191, 205, 219));
//                table_process->item(index,1)->setBackgroundColor(QColor(191, 205, 219));
//                table_process->item(index,2)->setBackgroundColor(QColor(191, 205, 219));
//                table_process->item(index,3)->setBackgroundColor(QColor(191, 205, 219));
//                table_process->item(index,4)->setBackgroundColor(QColor(191, 205, 219));
//                table_process->item(index,5)->setBackgroundColor(QColor(191, 205, 219));
//            }
            table_process->item(index,3)->setText(iter->value("Threads"));
            table_process->item(index,4)->setText(iter->value("Memory")=="0"?"-":iter->value("Memory"));
            table_process->item(index,5)->setText(iter->value("Cmd"));

            table_process->item(index,6)->setText(iter->value("PPID"));
            processLog.append(iter->value("PID"));
        }
    }

    for(int i=table_process->rowCount()-1;i>=0;i--){
        if(!processLog.contains(table_process->item(i,1)->text())){
            table_process->removeRow(i);
        }
    }
    processResultMutex.unlock();
}

void MainWindow::processSort(int logicalIndex){
    processResultMutex.lock();
    table_process->sortByColumn(logicalIndex);
    processResultMutex.unlock();
}

void MainWindow::processSave(){
    if(configSelectProcessDir()){
        myprocessclass->save(myglobal::process_save_dir);
    }
}

void MainWindow::processSaveMessage(int type,QString message){
    if(type == 0){
        QMessageBox::information(this,"提示",message);
    }else{
        QMessageBox::warning(this,"错误",message);
    }
}

void MainWindow::updateWiresharkDiag(QString srcip_type,unsigned char byMediaStatus0,unsigned char byMediaStatus1,unsigned char byLinkStatus0,unsigned char byLinkStatus1,unsigned char byNetSpeed0,unsigned char byNetSpeed1,
                                     unsigned char byDuplex0,unsigned char byDuplex1,unsigned char byBurthenOver0,unsigned char byBurthenOver1,unsigned char byAbnormityNode0,unsigned char byAbnormityNode1,
                                     unsigned char byInterCom,unsigned char byAddrCollision,unsigned char bySntpError,unsigned char byWorkMode){
    int num= table_wireshark->rowCount();



    auto tmplist = srcip_type.split("_");

    if(tmplist.length()!=2)return;

    QString diagType = tmplist[1];
    QString ip_src= tmplist[0];

    QString tmp="";

    for(int i=0;i<num;i++){
        if(table_wireshark->item(i,0)->text()==ip_src && table_wireshark->item(i,1)->text()==diagType){
            tmp  = byMediaStatus0==0?"ERROR":"GOOD";
            tmp += " / ";
            tmp += byMediaStatus1==0?"ERROR":"GOOD";
            table_wireshark->item(i,2)->setText(tmp);

            tmp  = byLinkStatus0==0?"NOLINK":"LINK";
            tmp += " / ";
            tmp += byLinkStatus1==0?"NOLINK":"LINK";
            table_wireshark->item(i,3)->setText(tmp);

            tmp  = byNetSpeed0==0?"10M":"100M";
            tmp += " / ";
            tmp += byNetSpeed1==0?"10M":"100M";
            table_wireshark->item(i,4)->setText(tmp);

            tmp  = byDuplex0==0?"HALF":"FULL";
            tmp += " / ";
            tmp += byDuplex1==0?"HALF":"FULL";
            table_wireshark->item(i,5)->setText(tmp);

            tmp  = byBurthenOver0==0?"正常":"负荷过重";
            tmp += " / ";
            tmp += byBurthenOver1==0?"正常":"负荷过重";
            table_wireshark->item(i,6)->setText(tmp);

            tmp  = byAbnormityNode0==0?"正常":"存在异常节点";
            tmp += " / ";
            tmp += byAbnormityNode1==0?"正常":"存在异常节点";
            table_wireshark->item(i,7)->setText(tmp);

            if(byInterCom==0x80){
                tmp = "2->1交错";
            }else if(byInterCom==0x40){
                tmp = "1->2交错";
            }else{
                tmp = "正常";
            }
            table_wireshark->item(i,8)->setText(tmp);

            tmp  = byAddrCollision==0?"正常":"节点冲突";
            table_wireshark->item(i,9)->setText(tmp);

            tmp  = bySntpError==0?"正常":"无时钟服务器";
            table_wireshark->item(i,10)->setText(tmp);

            if(byWorkMode==0x00){
                tmp = "备用";
            }else if(byInterCom==0x40){
                tmp = "工作";
            }else{
                tmp = "未知";
            }
            table_wireshark->item(i,11)->setText(tmp);
            table_wireshark->scrollToBottom();
            return;
        }
    }

    table_wireshark->insertRow(num);

    for(int i=0;i<15;i++){
        table_wireshark->setItem(num,i,new QTableWidgetItem());
    }

    table_wireshark->item(num,0)->setText(ip_src);
    table_wireshark->item(num,1)->setText(diagType);

    tmp  = byMediaStatus0==0?"ERROR":"GOOD";
    tmp += " / ";
    tmp += byMediaStatus1==0?"ERROR":"GOOD";
    table_wireshark->item(num,2)->setText(tmp);

    tmp  = byLinkStatus0==0?"NOLINK":"LINK";
    tmp += " / ";
    tmp += byLinkStatus1==0?"NOLINK":"LINK";
    table_wireshark->item(num,3)->setText(tmp);

    tmp  = byNetSpeed0==0?"10M":"100M";
    tmp += " / ";
    tmp += byNetSpeed1==0?"10M":"100M";
    table_wireshark->item(num,4)->setText(tmp);

    tmp  = byDuplex0==0?"HALF":"FULL";
    tmp += " / ";
    tmp += byDuplex1==0?"HALF":"FULL";
    table_wireshark->item(num,5)->setText(tmp);

    tmp  = byBurthenOver0==0?"正常":"负荷过重";
    tmp += " / ";
    tmp += byBurthenOver1==0?"正常":"负荷过重";
    table_wireshark->item(num,6)->setText(tmp);

    tmp  = byAbnormityNode0==0?"正常":"存在异常节点";
    tmp += " / ";
    tmp += byAbnormityNode1==0?"正常":"存在异常节点";
    table_wireshark->item(num,7)->setText(tmp);

    if(byInterCom==0x80){
        tmp = "2->1交错";
    }else if(byInterCom==0x40){
        tmp = "1->2交错";
    }else{
        tmp = "正常";
    }
    table_wireshark->item(num,8)->setText(tmp);

    tmp  = byAddrCollision==0?"正常":"节点冲突";
    table_wireshark->item(num,9)->setText(tmp);

    tmp  = bySntpError==0?"正常":"无时钟服务器";
    table_wireshark->item(num,10)->setText(tmp);

    if(byWorkMode==0x00){
        tmp = "备用";
    }else if(byInterCom==0x40){
        tmp = "工作";
    }else{
        tmp = "未知";
    }

    table_wireshark->item(num,11)->setText(tmp);
    table_wireshark->scrollToBottom();

    mynetchart * tmpchart = new mynetchart();       //新建图表，插入列表
    tmpchart->sip_type=srcip_type;
    tmpchart->setWindowTitle(srcip_type);
    mynetchartlist.append(tmpchart);

//    QMutex * tmpMutex = new QMutex();               //新建锁，插入列表
//    QPair<QString,QMutex*>* tmpPair = new QPair<QString,QMutex*>();
//    tmpPair->first=srcip_type;
//    tmpPair->second=tmpMutex;
//    myglobal::mywiresharkMutexList.append(tmpPair);

    connect(mywiresharkcheckclass,&mywiresharkCheck::signal_netchart,tmpchart,&mynetchart::updateData);
    mynetchartlist.append(tmpchart);


//    tmpchart->show();

}

void MainWindow::showNetChart(int row, int column){
    if(mynetchartlist.length()>row){
        if(mynetchartlist[row]!=nullptr){
            mynetchartlist[row]->show();
        }
    }
}


int MainWindow::configSelect900ProjectDir(){

    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFile);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择SafeContrix组态工程文件");
    dialog.setDirectory(myglobal::project_900_sisPrj);
    dialog.setNameFilter("sisPrj文件(*.sisPrj)");
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();

        myglobal::project_900_sisPrj = dirname[0];
        return 1;
    }
    return 0;
}










