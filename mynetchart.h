#ifndef MYNETCHART_H
#define MYNETCHART_H

#include <QObject>
#include <QWidget>
#include <QString>
#include <QSplineSeries>
#include <QChart>
#include <QList>
#include <QChartView>
#include <QValueAxis>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QApplication>
#include <QMenu>
#include <QAction>
#include <QFileDialog>
#include "mywireshark.h"
#include "myglobal.h"
#include "myunit.h"

#define NETCHARTLINE 14

QT_CHARTS_USE_NAMESPACE
class mynetchart: public QWidget {

Q_OBJECT

public:
    mynetchart();
    QChart* chart;
    QChartView* chartView;
//    QList<QList<double>*>data;
//    QList<QString>dataName;

    QCheckBox *wStatAll0,*wStatAll1,*dwStatALLByte0,*dwStatALLByte1,*wStatBroadcast0,*wStatBroadcast1;
    QCheckBox *wStatMulticast0,*wStatMulticast1,*wUnicast0,*wUnicast1;
    QCheckBox *wStatErr0,*wStatErr1,*wSBUSUnicast0,*wSBUSUnicast1;

    QMenu * pop_menu;
    QAction * save_action;

    QString sip_type;

    void initLayout();

public slots:
    void updateData(QString key);
    void updateMaxY();
    void setVisible(int stat);
    void savePic();
    void contextMenuEvent(QContextMenuEvent *event);
    int configSelectLogDir();

private:
    int maxX,maxY,maxSize;
    QList<QSplineSeries*>splineSeries;

    int visible[NETCHARTLINE];

};

#endif // MYNETCHART_H
