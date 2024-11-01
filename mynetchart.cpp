#include "mynetchart.h"


mynetchart::mynetchart()
{

    initLayout();
    maxX=30;
    maxY=10;
    maxSize=maxX+1;

    for(int i=0;i<NETCHARTLINE;i++){
        visible[i]=0;
    }


    chartView->setRenderHint(QPainter::Antialiasing);

    for(int i=0;i< NETCHARTLINE;i++){
        splineSeries.append(new QSplineSeries());
    }
    //界面上显示时用到

    splineSeries[0]->setName("0#网络平均每秒包数");
    splineSeries[1]->setName("1#网络平均每秒包数");

    splineSeries[2]->setName("0#网络平均每秒字节数");
    splineSeries[3]->setName("1#网络平均每秒字节数");

    splineSeries[4]->setName("0#网络平均每秒广播包数");
    splineSeries[5]->setName("1#网络平均每秒广播包数");

    splineSeries[6]->setName("0#网络平均每秒多播包数");
    splineSeries[7]->setName("1#网络平均每秒多播包数");

    splineSeries[8]->setName("0#网络平均每秒点播包数");
    splineSeries[9]->setName("1#网络平均每秒点播包数");

    splineSeries[10]->setName("0#网络平均每秒错包数");
    splineSeries[11]->setName("1#网络平均每秒错包数");

    splineSeries[12]->setName("0#网络SBUS数据每秒包数");
    splineSeries[13]->setName("1#网络SBUS数据每秒包数");


    QValueAxis *axisX = new QValueAxis();

    axisX->setRange(0, maxX);
    axisX->setTickCount(7);
    axisX->setMinorTickCount(4);
    axisX->setLabelFormat(" ");

    QValueAxis *axisY = new QValueAxis();
    axisY->setRange(0, maxY);
    axisY->setTickCount(6);
    axisY->setMinorTickCount(4);

    chart->legend()->setAlignment(Qt::AlignRight );

    for(int i=0;i<splineSeries.length();i++){
        chart->addSeries(splineSeries[i]);
        chart->setAxisX(axisX,splineSeries[i]);
        chart->setAxisY(axisY,splineSeries[i]);
    }
}

void mynetchart::initLayout(){

    this->resize(900,600);

    pop_menu = new QMenu();
    save_action = new QAction(this);

    chart=new QChart();
    chartView = new QChartView(chart);

    wStatAll0 = new QCheckBox("#0网络平均每秒包数");
    wStatAll1 = new QCheckBox("#1网络平均每秒包数");
    dwStatALLByte0 = new QCheckBox("#0网络平均每秒字节数");
    dwStatALLByte1 = new QCheckBox("#1网络平均每秒字节数");
    wStatBroadcast0 = new QCheckBox("#0网络平均每秒广播包数");
    wStatBroadcast1 = new QCheckBox("#1网络平均每秒广播包数");
    wStatMulticast0 = new QCheckBox("#0网络平均每秒多播包数");
    wStatMulticast1 = new QCheckBox("#1网络平均每秒多播包数");
    wUnicast0 = new QCheckBox("#0网络平均每秒点播包数");
    wUnicast1 = new QCheckBox("#1网络平均每秒点播包数");
    wStatErr0 = new QCheckBox("#0网络平均每秒错包数");
    wStatErr1 = new QCheckBox("#1网络平均每秒错包数");
    wSBUSUnicast0 = new QCheckBox("#0网络SBUS数据每秒包数");
    wSBUSUnicast1 = new QCheckBox("#1网络SBUS数据每秒包数");

    connect(wStatAll0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatAll1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(dwStatALLByte0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(dwStatALLByte1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatBroadcast0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatBroadcast1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatMulticast0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatMulticast1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wUnicast0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wUnicast1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatErr0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wStatErr1,&QCheckBox::stateChanged,this,&mynetchart::setVisible);
    connect(wSBUSUnicast0,&QCheckBox::stateChanged,this,&mynetchart::setVisible);

    connect(save_action, &QAction::triggered, this, &mynetchart::savePic);


    QVBoxLayout* v=new QVBoxLayout();
    this->setLayout(v);


    QHBoxLayout* h1=new QHBoxLayout();

    v->addLayout(h1);
    v->setAlignment(Qt::AlignTop);

    QGridLayout* g=new QGridLayout();


    g->addWidget(wStatAll0,0,0,1,1);
    g->addWidget(dwStatALLByte0,1,0,1,1);
    g->addWidget(wStatBroadcast0,2,0,1,1);
    g->addWidget(wStatMulticast0,3,0,1,1);

    g->addWidget(wUnicast0,0,1,1,1);
    g->addWidget(wStatErr0,1,1,1,1);
    g->addWidget(wSBUSUnicast0,2,1,1,1);

    g->addWidget(wStatAll1,0,2,1,1);
    g->addWidget(dwStatALLByte1,1,2,1,1);
    g->addWidget(wStatBroadcast1,2,2,1,1);
    g->addWidget(wStatMulticast1,3,2,1,1);

    g->addWidget(wUnicast1,0,3,1,1);
    g->addWidget(wStatErr1,1,3,1,1);
    g->addWidget(wSBUSUnicast1,2,3,1,1);

    v->addLayout(g);

    v->addWidget(chartView);



}

void mynetchart::updateMaxY(){
    double dataMax=10;
    for(int i=0;i<splineSeries.length();i++){
        QList<QPointF>tmp =splineSeries[i]->points();
        for(int j=0;j<tmp.length();j++){
            if(tmp[j].y()>dataMax){
                dataMax=tmp[j].y();
            }
        }
    }

    maxY=int(dataMax/4)*5;
    chart->axisY()->setRange(0, maxY);
}

void mynetchart::setVisible(int stat){
    visible[0]=wStatAll0->isChecked();
    visible[1]=wStatAll1->isChecked();
    visible[2]=dwStatALLByte0->isChecked();
    visible[3]=dwStatALLByte1->isChecked();
    visible[4]=wStatBroadcast0->isChecked();
    visible[5]=wStatBroadcast1->isChecked();
    visible[6]=wStatMulticast0->isChecked();
    visible[7]=wStatMulticast1->isChecked();
    visible[8]=wUnicast0->isChecked();
    visible[9]=wUnicast1->isChecked();
    visible[10]=wStatErr0->isChecked();
    visible[11]=wStatErr1->isChecked();
    visible[12]=wSBUSUnicast0->isChecked();
    updateData(sip_type);

}


void mynetchart::updateData(QString key){
    if(key != sip_type){
        return;
    }

    for(int i=0;i<NETCHARTLINE;i++){
        splineSeries[i]->clear();
    }


    bool ok;
    QMap<QString,QMap<QString,QStringList>>::iterator iter;

    for(int i=0;i<myglobal::mywiresharkclasslist.length();i++){
//        if(myglobal::mywiresharkclasslist[i]->getActive()==0)continue;

        for(iter=myglobal::mywiresharkclasslist[i]->udp1919.begin(); iter!=myglobal::mywiresharkclasslist[i]->udp1919.end();++iter){

            if(iter.key() == key){                          //找到该图表对应的数据

                int dataLen = iter.value()["dwRunTime"].length();
                if(dataLen<maxSize){
                    for(int j=0;j<dataLen;j++){
                        if(visible[0]){
                            splineSeries[0]->append(maxSize-dataLen+j,iter.value()["wStatAll0"][0].toInt(&ok));
                        }
                        if(visible[1]){
                            splineSeries[1]->append(maxSize-dataLen+j,iter.value()["wStatAll1"][0].toInt(&ok));
                        }
                        if(visible[2]){
                            splineSeries[2]->append(maxSize-dataLen+j,iter.value()["dwStatALLByte0"][0].toInt(&ok));
                        }
                        if(visible[3]){
                            splineSeries[3]->append(maxSize-dataLen+j,iter.value()["dwStatALLByte1"][0].toInt(&ok));
                        }
                        if(visible[4]){
                            splineSeries[4]->append(maxSize-dataLen+j,iter.value()["wStatBroadcast0"][0].toInt(&ok));
                        }
                        if(visible[5]){
                            splineSeries[5]->append(maxSize-dataLen+j,iter.value()["wStatBroadcast1"][0].toInt(&ok));
                        }
                        if(visible[6]){
                            splineSeries[6]->append(maxSize-dataLen+j,iter.value()["wStatMulticast0"][0].toInt(&ok));
                        }
                        if(visible[7]){
                            splineSeries[7]->append(maxSize-dataLen+j,iter.value()["wStatMulticast1"][0].toInt(&ok));
                        }
                        if(visible[8]){
                            splineSeries[8]->append(maxSize-dataLen+j,iter.value()["wUnicast0"][0].toInt(&ok));
                        }
                        if(visible[9]){
                            splineSeries[9]->append(maxSize-dataLen+j,iter.value()["wUnicast1"][0].toInt(&ok));
                        }
                        if(visible[10]){
                            splineSeries[10]->append(maxSize-dataLen+j,iter.value()["wStatErr0"][0].toInt(&ok));
                        }
                        if(visible[11]){
                            splineSeries[11]->append(maxSize-dataLen+j,iter.value()["wStatErr1"][0].toInt(&ok));
                        }
                        if(visible[12]){
                            splineSeries[12]->append(maxSize-dataLen+j,iter.value()["wSBUSUnicast0"][0].toInt(&ok));
                        }
                        if(visible[13]){
                            splineSeries[13]->append(maxSize-dataLen+j,iter.value()["wSBUSUnicast1"][0].toInt(&ok));
                        }

                    }
                }else{
                    for(int j=0;j<maxSize;j++){
                        if(visible[0]){
                            splineSeries[0]->append(j,iter.value()["wStatAll0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[1]){
                            splineSeries[1]->append(j,iter.value()["wStatAll1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[2]){
                            splineSeries[2]->append(j,iter.value()["dwStatALLByte0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[3]){
                            splineSeries[3]->append(j,iter.value()["dwStatALLByte1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[4]){
                            splineSeries[4]->append(j,iter.value()["wStatBroadcast0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[5]){
                            splineSeries[5]->append(j,iter.value()["wStatBroadcast1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[6]){
                            splineSeries[6]->append(j,iter.value()["wStatMulticast0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[7]){
                            splineSeries[7]->append(j,iter.value()["wStatMulticast1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[8]){
                            splineSeries[8]->append(j,iter.value()["wUnicast0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[9]){
                            splineSeries[9]->append(j,iter.value()["wUnicast1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[10]){
                            splineSeries[10]->append(j,iter.value()["wStatErr0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[11]){
                            splineSeries[11]->append(j,iter.value()["wStatErr1"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[12]){
                            splineSeries[12]->append(j,iter.value()["wSBUSUnicast0"][dataLen-maxSize+j].toInt(&ok));
                        }
                        if(visible[13]){
                            splineSeries[13]->append(j,iter.value()["wSBUSUnicast1"][dataLen-maxSize+j].toInt(&ok));
                        }

                    }
                }
                updateMaxY();
                return;
            }
        }
    }



}

void mynetchart::contextMenuEvent(QContextMenuEvent *event)

{
    //清除原有菜单

    pop_menu->clear();
    pop_menu->addAction(save_action);
    save_action->setText(QString("保存图片"));
    //菜单出现的位置为当前鼠标的位置

    pop_menu->exec(QCursor::pos());
    event->accept();

}

void mynetchart::savePic(){
    if(configSelectLogDir()){

        QString path=myglobal::log_save_dir;
        myunit::mkdir(path);

        QPixmap p = QPixmap::grabWidget(this);
        QImage image=p.toImage();
        image.save(path+QString("/"+sip_type+".png"));
    }
}


int mynetchart::configSelectLogDir(){
    QFileDialog dialog(nullptr);
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setWindowTitle("选择图片保存路径");
    dialog.setDirectory(myglobal::log_save_dir);
    if(dialog.exec()){
        QStringList dirname = dialog.selectedFiles();
        myglobal::log_save_dir=dirname[0];
        return 1;
    }
    return 0;
}




















