#include "mychart.h"
#include <QDebug>
mychart::mychart(QString etcardName,int netcardNum,QWidget *parent){

    for(int i=0;i<STRUCTSIZE+OTHER_HCOUNTER;i++)
        visible[i]=0;

    maxX=30;
    maxY=10;
    maxSize=maxX+1;
    this->netcardNum=netcardNum;

    chart=new QChart();
    chartView = new QChartView(chart);

    chartView->setRenderHint(QPainter::Antialiasing);

    QStringList netcardNames=etcardName.split(',');
    for(int i=0;i<OTHER_HCOUNTER;i++){
        splineSeries.append(new QSplineSeries());
    }
    splineSeries[0]->setName("CPU占用:(%)");      //界面上显示时用到
    splineSeries[1]->setName("可用内存:(GB)");
    splineSeries[2]->setName("硬盘读占用率:(%)");
    splineSeries[3]->setName("硬盘写占用率:(%)");

//    splineSeries[0]->setColor(QColor())
//    splineSeries[1]->setColor(QColor(0x20,0x9f,0xdf));

    dataName.append("CPU占用:(%)");               //数据导出的时候用到
    dataName.append("可用内存:(MB)");
    dataName.append("硬盘读占用率:(%)");
    dataName.append("硬盘写占用率:(%)");

    data.append(new QList<double>());
    data.append(new QList<double>());
    data.append(new QList<double>());
    data.append(new QList<double>());

//    QColor colors[]={QColor(0xe5,0x4d,0x42),
//                       QColor(0xf3,0x7b,0x1d),
//                       QColor(0xfb,0xbd,0x08),
//                       QColor(0x8d,0xc6,0x3f),
//                       QColor(0x39,0xb5,0x4a),
//                       QColor(0x1c,0xbb,0xb4),
//                       QColor(0xbf,0x59,0x3e),
//                       QColor(0x9c,0x26,0xb0),
//                       QColor(254,67,101),
//                       QColor(252,157,154),
//                       QColor(249,205,173),
//                       QColor(200,200,169)};

    for(int i=0;i<netcardNum;i++){
        QSplineSeries* splineSeries1=new QSplineSeries();
        splineSeries1->setName(QString("网卡")+QString::number(i+1)+QString(":KB/s(收)"));
//        splineSeries1->setColor(colors[i%sizeof (colors)]);
        splineSeries.append(splineSeries1);

        dataName.append(QString("网卡")+QString::number(i+1)+":"+QString(netcardNames[i])+QString(":Bytes/s(收)"));
        data.append(new QList<double>());


        QSplineSeries* splineSeries2=new QSplineSeries();
        splineSeries2->setName(QString("网卡")+QString::number(i+1)+QString(":KB/s(发)"));
//        splineSeries2->setColor(colors[(i+1)%sizeof (colors)]);
        splineSeries.append(splineSeries2);
        dataName.append(QString("网卡")+QString::number(i+1)+":"+QString(netcardNames[i])+QString(":Bytes/s(发)"));
        data.append(new QList<double>());

        QSplineSeries* splineSeries3=new QSplineSeries();
        splineSeries3->setName(QString("网卡")+QString::number(i+1)+QString(":P/s(收)"));
//        splineSeries3->setColor(colors[(i+2)%sizeof (colors)]);
        splineSeries.append(splineSeries3);
        dataName.append(QString("网卡")+QString::number(i+1)+":"+QString(netcardNames[i])+QString(":Packets/s(收)"));
        data.append(new QList<double>());

        QSplineSeries* splineSeries4=new QSplineSeries();
        splineSeries4->setName(QString("网卡")+QString::number(i+1)+QString(":P/s(发)"));
//        splineSeries4->setColor(colors[(i+3)%sizeof (colors)]);
        splineSeries.append(splineSeries4);
        dataName.append(QString("网卡")+QString::number(i+1)+":"+QString(netcardNames[i])+QString(":Packets/s(发)"));
        data.append(new QList<double>());
    }

//    chart->createDefaultAxes();

    QValueAxis *axisX = new QValueAxis();

    axisX->setRange(0, maxX);
    axisX->setTickCount(7);
    axisX->setMinorTickCount(4);
    axisX->setLabelFormat(" ");
//    chart->addAxis(axisX,Qt::AlignBottom);

    QValueAxis *axisY = new QValueAxis();
    axisY->setRange(0, maxY);
    axisY->setTickCount(6);
    axisY->setMinorTickCount(4);

//    chart->addAxis(axisY,Qt::AlignLeft);

    chart->legend()->setAlignment(Qt::AlignRight );

    for(int i=0;i<splineSeries.length();i++){
        chart->addSeries(splineSeries[i]);
        chart->setAxisX(axisX,splineSeries[i]);
        chart->setAxisY(axisY,splineSeries[i]);
    }


}


void mychart::updateData(int i,double value){
    if(i==-1){
        for(int j=0;j<splineSeries.length();j++){
            data[j]->clear();
        }
    }
    if(i<0 || i>=OTHER_HCOUNTER+4*netcardNum)return;

    splineSeries[i]->clear();

//    if (data[i]->size()>=maxSize){
//        data[i]->pop_front();
//    }
    data[i]->append(value);

    if(visible[i]!=1)return;



    int dividend=1;
    if (i==1 || (i>=OTHER_HCOUNTER && ((i-OTHER_HCOUNTER) % 4 ==0 || (i-OTHER_HCOUNTER) % 4 ==1))){
        dividend=1024;
    }

    int dataLen = data[i]->length();

    if(dataLen<maxSize){
        for(int j=0;j<dataLen;j++){
            splineSeries[i]->append(maxSize-dataLen+j,(*data[i])[j]/dividend);
        }
    }else{
        for(int j=0;j<maxSize;j++){
            splineSeries[i]->append(j,(*data[i])[dataLen-maxSize+j]/dividend);
        }
    }



}

void mychart::updateMaxY(){
    double dataMax=10;
    for(int i=0;i<splineSeries.length();i++){
        QList<QPointF>tmp =splineSeries[i]->points();
        for(int j=0;j<tmp.length();j++){
            if(tmp[j].y()>dataMax){
                dataMax=tmp[j].y();
            }
        }
    }

    maxY=int(dataMax*1.2/5)*5;
    chart->axisY()->setRange(0, maxY);
}

void mychart::setVisible(int index,bool flag){
    int value=0;
    if(flag)value=1;
    int i=0;
    if(index<OTHER_HCOUNTER){
        i=index;
        visible[i]=value;
    }
    else {
        i=(index-OTHER_HCOUNTER)*4+OTHER_HCOUNTER;
        visible[i]=value;
        visible[i+1]=value;
        visible[i+2]=value;
        visible[i+3]=value;
    }
}















