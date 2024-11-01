#ifndef MYWIRESHARK_H
#define MYWIRESHARK_H

#include <QObject>
#include <QThread>
#include <QMap>
#include <QList>
#include <QDateTime>

#include <QDebug>
#include"pcap.h"
#define PKT_MAX_LEN 65535
#define PKT_TIMEOUT 1000
#define PKT_ETH_MODE false


#define IPTOSBUFFERS  12

#define IP_UDP          0x11    //UDP为17
#define IP_TCP          0x06    //TCP为6
#define ETH_ARP         0x0608  //ARP为0x0806
#define ETH_IPV4        0x0008  //IPV4为0x0800
#define ARP_HARDWARE    1
#define ARP_REQUEST     0x0100  //ARP请求
#define ARP_REPLY       0x0200  //ARP应答

#define MULTICAST 2 //多播
#define BROADCAST 1 //广播
#define UNICAST 3 //点播

typedef struct ethhdr
{
    u_int8_t dhost[6]; //目的Mac地址
    u_int8_t shost[6]; //源Mac地址
    u_int16_t type;    //协议类型
}ETH_HDR;

typedef struct arp_hder {
    unsigned short HardwareType; //硬件类型
    unsigned short ProtocolType; //协议类型
    unsigned char HardwareAddLen; //硬件地址长度
    unsigned char ProtocolAddLen; //协议地址长度
    unsigned short OperationField; //操作字段
    unsigned char SourceMacAdd[6]; //源mac地址
    unsigned char SourceIpAdd[4]; //源ip地址
    unsigned char DestMacAdd[6]; //目的mac地址
    unsigned char DestIpAdd[4]; //目的ip地址
}ARP_HDR;

typedef struct ip_hdr   //IP头
{
  u_int8_t   header_length:4,
             version:4;

  u_int8_t    tos;
  u_int16_t    length;
//  u_int8_t    length1;
//  u_int8_t    length2;
  u_int16_t   id;
  u_int16_t   off;
  u_int8_t    ttl;
  u_int8_t    proto;
  u_int16_t   checksum;
  struct in_addr souce_addr;
  struct in_addr dest_addr;
}IP_HDR;


typedef struct udp_hdr
{
    unsigned short sport;
    unsigned short dport;
    unsigned short length;
    unsigned short checksum;
}UDP_HDR;


typedef struct tcp_hdr  //TCP头
{
    unsigned short sport; //16位源端口
    unsigned short dport; //16位目的端口
    unsigned int seq; //32位序列号
    unsigned int ack; //32位确认号
    unsigned char lenres; //4位首部长度/6位保留字
    unsigned char flag; //6位标志位
    unsigned short win; //16位窗口大小
    unsigned short sum; //16位校验和
    unsigned short urp; //16位紧急数据偏移量
}TCP_HDR;

class mywireshark:public QThread
{
    Q_OBJECT
public:
    QMap<QString,QMap<QString,QStringList>> udp1919;
//    QMap<QString,QStringList> udp3000;
//    QMap<QString,QStringList> udp6432;
    mywireshark();
    int getActive();
    void setActive(int active);
    void setDirName(QString dirName);
    void setNetcardDescript(QString descript);
    void setNetcard(QString tag);
    QStringList getNetcards();
    bool setFilter(QString filter);
//    unsigned long totalPackets=0,totalBytes=0,totalBoardcast=0,totalMulticast=0,totalUnicast=0;
    void setStop(int level);


public:
signals:
    //0:error
    //1:normal
    void signal_wireshark(int level,QString tag);
    void signal_net(QString ip_src,unsigned char byMediaStatus0,unsigned char byMediaStatus1,unsigned char byLinkStatus0,unsigned char byLinkStatus1,unsigned char byNetSpeed0,unsigned char byNetSpeed1,unsigned char byDuplex0,unsigned char byDuplex1,unsigned char byBurthenOver0,unsigned char byBurthenOver1,unsigned char byAbnormityNode0,unsigned char byAbnormityNode1,unsigned char byInterCom,unsigned char byAddrCollision,unsigned char bySntpError,unsigned char byWorkMode);
    void signal_addARP(QString psrc,QString hwsrc);
    void signal_total(int type);
    void signal_checkMAC(QString ip,QString mac);

private:
    void run();
    int active=0,level=0;
    int index=0;//记录当前是第几个pcap文件
    QString startPcapTime;
    QString netcardName,netcardDescript;
    QString dirName;
    QString filter;

    int createPcapFile(pcap_dumper_t **dumpfile,pcap_t *adhandle);
    char *iptos(u_long in);
    void packet_handler(const struct pcap_pkthdr *header, const u_char *pkt_data);
//    void ifprint(pcap_if_t *d);
    int isMulticast(QString inputstr);

};

#endif // MYWIRESHARK_H
