#include "myping.h"

USHORT myping::s_usPacketSeq = 0;
QMutex myping::pingSeqMutex;
myping::myping() :m_szICMPData(nullptr),m_bIsInitSucc(FALSE)
{
    WSADATA WSAData;
    //WSAStartup(MAKEWORD(2, 2), &WSAData);
    if (WSAStartup(MAKEWORD(1, 1), &WSAData) != 0 || WSAStartup(MAKEWORD(2, 2), &WSAData)!=0)
    {
//        QMessageBox::warning(nullptr,"错误",QString("WSAStartup失败！"));
//        printf("WSAStartup() failed: %d\n", GetLastError());
        return;
    }
    m_event = WSACreateEvent();
    m_usCurrentProcID = (USHORT)GetCurrentProcessId();

    m_sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, nullptr, 0, 0);
    if (m_sockRaw == INVALID_SOCKET)
    {
//        QMessageBox::warning(nullptr,"错误",QString("WSASocket失败！"));
        //std::cerr << "WSASocket() failed:" << WSAGetLastError ()<< std::endl;  //10013 以一种访问权限不允许的方式做了一个访问套接字的尝试。
    }
    else
    {
        WSAEventSelect(m_sockRaw, m_event, FD_READ);
        m_bIsInitSucc = TRUE;

        m_szICMPData = (char*)malloc(DEF_PACKET_SIZE + sizeof(ICMPHeader));

        if (m_szICMPData == nullptr)
        {
            m_bIsInitSucc = FALSE;
        }
    }
}

myping::~myping()
{
    WSACleanup();

    if (nullptr != m_szICMPData)
    {
        free(m_szICMPData);
        m_szICMPData = nullptr;
    }
}

BOOL myping::PingCore(const char *szDestIP, PingReply *pPingReply, DWORD dwTimeout)
{
    //判断初始化是否成功
    if (!m_bIsInitSucc)
    {
        return FALSE;
    }

    ULONG ulSendTimestamp = GetTickCountCalibrate();

    u_long ulDestIP = inet_addr(szDestIP);
    //转换不成功时按域名解析

//    if (ulDestIP == INADDR_NONE)
//    {
//        hostent *pHostent = gethostbyname(szDestIP);
//        if (pHostent)
//        {
//            ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
//        }
//        else
//        {
//            return 0;
//        }
//    }

    //配置SOCKET

    sockaddr_in sockaddrDest;
    sockaddrDest.sin_family = AF_INET;
    sockaddrDest.sin_addr.s_addr = ulDestIP;
    int nSockaddrDestSize = sizeof(sockaddrDest);


    //构建ICMP包
    int nICMPDataSize = DEF_PACKET_SIZE + sizeof(ICMPHeader);

    pingSeqMutex.lock();
    USHORT usSeq = ++s_usPacketSeq;
    pingSeqMutex.unlock();

    memset(m_szICMPData, 0, nICMPDataSize);
    ICMPHeader *pICMPHeader = (ICMPHeader*)m_szICMPData;
    pICMPHeader->m_byType = ECHO_REQUEST;
    pICMPHeader->m_byCode = 0;
    pICMPHeader->m_usID = m_usCurrentProcID;
    pICMPHeader->m_usSeq = usSeq;

//    qDebug()<<"send node"<<node <<"usSeq"<<usSeq;

    pICMPHeader->m_ulTimeStamp = ulSendTimestamp;
    pICMPHeader->m_usChecksum = CalCheckSum((USHORT*)m_szICMPData, nICMPDataSize);


    //发送ICMP报文
//    qDebug()<<sockaddrDest.sin_addr;
    if (sendto(m_sockRaw, m_szICMPData, nICMPDataSize, 0, (struct sockaddr*)&sockaddrDest, nSockaddrDestSize) == SOCKET_ERROR)
    {
        return FALSE;
    }

    char recvbuf[256] = { "\0" };
    while (myglobal::pingActive)
    {
        //接收响应报文
        if (WSAWaitForMultipleEvents(1, &m_event, FALSE, 100, FALSE) != WSA_WAIT_TIMEOUT)
        {
            WSANETWORKEVENTS netEvent;
            WSAEnumNetworkEvents(m_sockRaw, m_event, &netEvent);

            if (netEvent.lNetworkEvents & FD_READ)
            {
                ULONG nRecvTimestamp = GetTickCountCalibrate();
                int nPacketSize = recvfrom(m_sockRaw, recvbuf, 256, 0, (struct sockaddr*)&sockaddrDest, &nSockaddrDestSize);
                if (nPacketSize != SOCKET_ERROR)
                {
                    IPHeader *pIPHeader = (IPHeader*)recvbuf;
                    USHORT usIPHeaderLen = (USHORT)((pIPHeader->m_byVerHLen & 0x0f) * 4);
                    ICMPHeader *pICMPHeader = (ICMPHeader*)(recvbuf + usIPHeaderLen);

                    if (pICMPHeader->m_usID == m_usCurrentProcID //是当前进程发出的报文
                        && pICMPHeader->m_byType == ECHO_REPLY //是ICMP响应报文
                        && pICMPHeader->m_usSeq == usSeq //是本次请求报文的响应报文
                        )
                    {
                        pPingReply->m_usSeq = usSeq;

//                        qDebug()<<"recv node"<<node <<"usSeq"<<usSeq;

                        pPingReply->m_dwRoundTripTime = nRecvTimestamp - pICMPHeader->m_ulTimeStamp;
                        pPingReply->m_dwBytes = nPacketSize - usIPHeaderLen - sizeof(ICMPHeader);
                        pPingReply->m_dwTTL = pIPHeader->m_byTTL;
                        return TRUE;
                    }
                }
            }
        }
        //超时
        if (GetTickCountCalibrate() - ulSendTimestamp >= dwTimeout)
        {
            return FALSE;
        }
    }
    return false;
}

USHORT myping::CalCheckSum(USHORT *pBuffer, int nSize)
{
    unsigned long ulCheckSum = 0;
    while (nSize > 1)
    {
        ulCheckSum += *pBuffer++;
        nSize -= sizeof(USHORT);
    }
    if (nSize)
    {
        ulCheckSum += *(UCHAR*)pBuffer;
    }

    ulCheckSum = (ulCheckSum >> 16) + (ulCheckSum & 0xffff);
    ulCheckSum += (ulCheckSum >> 16);

    return (USHORT)(~ulCheckSum);
}

ULONG myping::GetTickCountCalibrate()
{
    static ULONG s_ulFirstCallTick = 0;
    static LONGLONG s_ullFirstCallTickMS = 0;

    SYSTEMTIME systemtime;
    FILETIME filetime;
    GetLocalTime(&systemtime);
    SystemTimeToFileTime(&systemtime, &filetime);
    LARGE_INTEGER liCurrentTime;
    liCurrentTime.HighPart = filetime.dwHighDateTime;
    liCurrentTime.LowPart = filetime.dwLowDateTime;
    LONGLONG llCurrentTimeMS = liCurrentTime.QuadPart / 10000;

    if (s_ulFirstCallTick == 0)
    {
        s_ulFirstCallTick = GetTickCount();
    }
    if (s_ullFirstCallTickMS == 0)
    {
        s_ullFirstCallTickMS = llCurrentTimeMS;
    }

    return s_ulFirstCallTick + (ULONG)(llCurrentTimeMS - s_ullFirstCallTickMS);
}

void myping::setNode(int node,int netType){
    this->netType=netType;
    this->node=node;
    switch(netType){
        case 0:this->ip=myglobal::ip_A+"."+QString::number(node);break;
        case 1:this->ip=myglobal::ip_B+"."+QString::number(node);break;
        case 2:this->ip=myglobal::ip_C+"."+QString::number(node);break;
    default:break;
    }

}

void myping::run(){
    int tmp=PINGCOUNT;
    BOOL ret =false;
    while(myglobal::pingActive && tmp--){
        PingReply result;
        result.m_dwRoundTripTime=-1;
        ret = PingCore(ip.toStdString().c_str(),&result,PINGTIMEOUT*1000);
        numOfSend+=1;
        if(ret == TRUE && result.m_dwRoundTripTime>=0)numOfRecv+=1;

        //qDebug()<<node<<numOfSend<<ret<<result.m_dwRoundTripTime<<numOfRecv;

        emit signal_pingResult(node,netType,result.m_dwRoundTripTime,numOfSend,numOfRecv);

        if(result.m_dwRoundTripTime<1000){
            Sleep(1000);
        }
    }
}








