#ifndef MYCHART_H
#define MYCHART_H

#endif // MYCHART_H
#include <QObject>
#include <QWidget>
#include <QString>
#include <QSplineSeries>
#include <QChart>
#include <QList>
#include <QChartView>
#include <QValueAxis>
#include "myheader.h"

//class DataItem{
//public:
//    QString name;
//    QList<double> value;
//    DataItem(QString name){
//        this->name=name;
//    }
//};



QT_CHARTS_USE_NAMESPACE
class mychart: public QObject {

Q_OBJECT

public:
    mychart(QString netcardName, int netcardNum,QWidget *parent = nullptr);
    QChart* chart;
    QChartView* chartView;
    QList<QList<double>*>data;
    QList<QString>dataName;

public slots:
    void updateData(int index,double value);
    void updateMaxY();
    void setVisible(int index,bool value);

private:
    int maxX,maxY,maxSize,netcardNum;
    QList<QSplineSeries*>splineSeries;
    int visible[STRUCTSIZE+OTHER_HCOUNTER];

};
