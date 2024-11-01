#-------------------------------------------------
#
# Project created by QtCreator 2020-08-18T11:59:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
QT += charts
QT += xml
QT += network
TARGET = netCheck
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

#QMAKE_LFLAGS += /MANIFESTUAC:"level='requireAdministrator'uiAccess='false'"
win32{
    RC_FILE=manifest.rc
}



SOURCES += \
        main.cpp \
        mainwindow.cpp \
    mychart.cpp \
    mydcom.cpp \
    myglobal.cpp \
    mynetchart.cpp \
    myperformance.cpp \
    myping.cpp \
    myinfo.cpp \
    myprocess.cpp \
    myrecommend.cpp \
    myunit.cpp \
    mywireshark.cpp \
    mywiresharkcheck.cpp \
    rbtableheaderview.cpp

HEADERS += \
        mainwindow.h \
    mydcom.h \
    myglobal.h \
    mynetchart.h \
    myping.h \
    myinfo.h \
    myperformance.h \
    myheader.h \
    mychart.h \
    myprocess.h \
    myrecommend.h \
    myunit.h \
    mywireshark.h \
    mywiresharkcheck.h \
    rbtableheaderview.h

FORMS += \
        mainwindow.ui
INCLUDEPATH += E:/QtWorkspace/quazip/include
INCLUDEPATH += E:/QtWorkspace/WpdPack/Include

LIBS += -lnetapi32
LIBS += -lPdh
LIBS += -lIphlpapi
LIBS += -lWS2_32
LIBS += -lPsapi
#LIBS += E:/QtWorkspace/WpdPack/Lib/x64/wpcap.lib
#LIBS += E:/QtWorkspace/WpdPack/Lib/x64/Packet.lib
LIBS += E:/QtWorkspace/WpdPack/Lib/wpcap.lib
LIBS += E:/QtWorkspace/WpdPack/Lib/Packet.lib

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32: LIBS += -L$$PWD/lib/32/ -lquazip
#win32: LIBS += -L$$PWD/lib/ -lzlibwapi

INCLUDEPATH += $$PWD/include
DEPENDPATH += $$PWD/include

DISTFILES += \
    manifest.rc \
    manifest.xml




