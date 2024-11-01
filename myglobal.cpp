#include "myglobal.h"

myglobal::myglobal()
{

}

int myglobal::pingActive=0;
bool myglobal::enable_A=false;
bool myglobal::enable_B=false;
bool myglobal::enable_C=false;
QString myglobal::ip_A="172.20.0";
QString myglobal::ip_B="172.21.0";
QString myglobal::ip_C="172.30.0";
QString myglobal::startTime="";
QString myglobal::info_save_dir;
QString myglobal::info_zip_save_dir;
QString myglobal::log_save_dir;
QString myglobal::wireshark_save_dir;
QString myglobal::process_save_dir;
QString myglobal::project_900_sisPrj;

QList<mywireshark*> myglobal::mywiresharkclasslist;
//QList<QPair<QString,QMutex*>*> myglobal::mywiresharkMutexList;
