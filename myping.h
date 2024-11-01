#ifndef MYPING_H
#define MYPING_H
#include <winsock2.h>

#define DEF_PACKET_SIZE 32
#define ECHO_REQUEST 8
#define ECHO_REPLY 0

#include <QMessageBox>
#include <QRunnable>
#include <QThread>
#include <QString>
#include <QtDebug>
#include <QMutex>
#include "myglobal.h"
struct IPHeader
{
    BYTE m_byVerHLen; //4位版本+4位首部长度
    BYTE m_byTOS; //服务类型
    USHORT m_usTotalLen; //总长度
    USHORT m_usID; //标识
    USHORT m_usFlagFragOffset; //3位标志+13位片偏移
    BYTE m_byTTL; //TTL
    BYTE m_byProtocol; //协议
    USHORT m_usHChecksum; //首部检验和
    ULONG m_ulSrcIP; //源IP地址
    ULONG m_ulDestIP; //目的IP地址
};

struct ICMPHeader
{
    BYTE m_byType; //类型
    BYTE m_byCode; //代码
    USHORT m_usChecksum; //检验和
    USHORT m_usID; //标识符
    USHORT m_usSeq; //序号
    ULONG m_ulTimeStamp; //时间戳（非标准ICMP头部）
};

struct PingReply
{
    USHORT m_usSeq;
    int m_dwRoundTripTime;
    int m_dwBytes;
    int m_dwTTL;
};

class myping: public QObject, public QRunnable
{
    Q_OBJECT
public:
    myping();
    ~myping();
    void setNode(int node,int netType);

private:
    BOOL PingCore(const char *szDestIP, PingReply *pPingReply, DWORD dwTimeout);
    USHORT CalCheckSum(USHORT *pBuffer, int nSize);
    ULONG GetTickCountCalibrate();
    void run();
    QString ip;
    SOCKET m_sockRaw;
    WSAEVENT m_event;
    USHORT m_usCurrentProcID;
    char *m_szICMPData;
    BOOL m_bIsInitSucc;
    static USHORT s_usPacketSeq;
    static QMutex pingSeqMutex;
    int netType,node;
    int numOfSend=0;
    int numOfRecv=0;

public:
signals:
    void signal_pingResult(int node,int type ,int delay,int numOfSend,int numOfRecv);
};

#endif // MYPING_H
