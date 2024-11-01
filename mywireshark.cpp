#include "mywireshark.h"

mywireshark::mywireshark()
{

}

void mywireshark::setNetcard(QString tag){
    netcardName=tag;
}

void mywireshark::setNetcardDescript(QString descript){
    netcardDescript=descript;       //类似Realtek USB NIC
}

void mywireshark::setActive(int active){
    this->active=active;
}

int mywireshark::getActive(){
    return active;
}

void mywireshark::setDirName(QString dirName){
    this->dirName=dirName;
}

void mywireshark::run(){
    active=1;

    pcap_t *adhandle;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dumpfile=NULL;


    if ( (adhandle= pcap_open_live(netcardName.toStdString().c_str(),/*d->name,*/ //设备名
        PKT_MAX_LEN, // 捕捉完整的数据包
        PKT_ETH_MODE, // 混杂模式
        PKT_TIMEOUT, // 读入超时
        errbuf // 错误缓冲
        ) ) == nullptr)
    {

        emit signal_wireshark(0,QString("打开适配器失败 ")+errbuf);
//        pcap_freealldevs(alldevs);
        active=0;
        return ;
    }


    u_int netmask;
    u_int net_ip;
    char error_content[PCAP_ERRBUF_SIZE] = {0};
    pcap_lookupnet(netcardName.toStdString().c_str(),&net_ip,&netmask,error_content);

    struct bpf_program fcode;

    if (pcap_compile(adhandle, &fcode, filter.toStdString().c_str(), 1, netmask) < 0)
    {
        emit signal_wireshark(0,QString("过滤条件编译失败 "));
//        pcap_freealldevs(alldevs);
        active=0;
        return ;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        emit signal_wireshark(0,QString("过滤条件设置失败"));
        active=0;
        return ;
    }

    startPcapTime = QDateTime::currentDateTime().toString("yyyyMMddhhmmss");


//    long long totalPcapLen=0;
    /* 开始捕捉 */
    if(createPcapFile(&dumpfile,adhandle)){
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res=0;
        long totalPacketCnt=0;
        long startTime=QDateTime::currentDateTime().toTime_t();
        long endTime;

        while(active){
            if(level==1){
                endTime=QDateTime::currentDateTime().toTime_t();
                if(endTime-startTime>=60*60)break;
            }


            res = pcap_next_ex(adhandle, &header, &pkt_data);

            if(res == 0)continue;

            packet_handler(header,pkt_data);

            pcap_dump((unsigned char*)dumpfile, header, pkt_data);
            //循环保存 不清楚什么原因异常
//            totalPcapLen+=header->caplen;
//            if(totalPcapLen >= 1024*1024 ){
//                totalPcapLen=0;
//                pcap_close(adhandle);
//                if(!createPcapFile(&dumpfile,adhandle)){
//                    goto error;
//                }
//            }

            if(level==2){
                totalPacketCnt+=1;
                if(totalPacketCnt>=1000)break;
            }
        }
        pcap_close(adhandle);

//        error:
        active=0;
        emit signal_wireshark(1,QString("停止抓包，网卡：")+netcardDescript);
    }
}

char* mywireshark::iptos(u_long in){
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;
    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

void mywireshark::packet_handler(const struct pcap_pkthdr *header, const u_char *pkt_data){
    ETH_HDR * eth_header;
    ARP_HDR * arp_header;
    IP_HDR* ip_head;
    TCP_HDR * tcp_head;
    UDP_HDR * udp_head;
    int packetType=UNICAST;


    eth_header=(ETH_HDR*)(pkt_data); //以太网
    QString eth_dest_mac="",eth_src_mac="";
    for(int i=0;i<6;i++){
        QString tmp=QString("%1").arg(eth_header->dhost[i],2,16,QLatin1Char('0'));
        if(eth_dest_mac.length()>1){
            eth_dest_mac=eth_dest_mac+"-"+tmp;
        }else{
            eth_dest_mac=tmp;
        }

        tmp=QString("%1").arg(eth_header->shost[i],2,16,QLatin1Char('0'));
        if(eth_src_mac.length()>1){
            eth_src_mac=eth_src_mac+"-"+tmp;
        }else{
            eth_src_mac=tmp;
        }
    }
    if(eth_dest_mac.toUpper()=="FF-FF-FF-FF-FF-FF"){
        packetType=BROADCAST;//广播
    }

    if(eth_header->type==ETH_ARP){  //ARP包
        arp_header=(ARP_HDR*)(pkt_data+sizeof(ETH_HDR));
        if(arp_header->OperationField==ARP_REPLY){
            QString arp_src_ip="",arp_src_mac="";

            for(int i=0;i<6;i++){
                QString tmp = QString("%1").arg(arp_header->SourceMacAdd[i], 2, 16, QLatin1Char('0'));
                if(arp_src_mac.length()>1){
                    arp_src_mac=arp_src_mac+"-"+tmp;
                }else{
                    arp_src_mac=tmp;
                }
            }

            for(int i=0;i<4;i++){
                QString tmp=QString::number(arp_header->SourceIpAdd[i]);
                if(arp_src_ip.length()>1){
                    arp_src_ip=arp_src_ip+"."+tmp;
                }else{
                    arp_src_ip=tmp;
                }
            }
            emit signal_addARP(arp_src_ip,arp_src_mac);
        }
    }

    if(eth_header->type==ETH_IPV4){ //IP包
        ip_head=(IP_HDR*)(pkt_data+sizeof(ETH_HDR));
        QString ip_src= inet_ntoa(ip_head->souce_addr);

        if(isMulticast(inet_ntoa(ip_head->dest_addr))){
            packetType=MULTICAST; //多播
        }
        emit signal_checkMAC(ip_src,eth_src_mac);

        if(ip_head->proto==IP_UDP){

            udp_head = (UDP_HDR*)((u_char*)ip_head+4*ip_head->header_length);

            int udp_sport = ntohs(udp_head->sport);
            int udp_dport = ntohs(udp_head->dport);

            if(packetType==MULTICAST && udp_sport==0x1919 && udp_dport==0x1919){

                //700 诊断包 168 组播    1秒/包
                //900 诊断包 170 组播 1秒/包

                QString diagType="";

                if(header->caplen == 168 || header->caplen==170){
                    if(header->caplen==168){
                        diagType = "700诊断包";
                    }else{
                        diagType = "900诊断包";
                    }

                    const u_char* scnet = pkt_data;

                    BYTE byMediaStatus0 = scnet[0x54];//网络接口状态 0：ERROR，1：GOOD
                    BYTE byMediaStatus1 = scnet[0x55];

                    BYTE byLinkStatus0 = scnet[0x56];//网口连接状态 0：NOLINK，1：LINK
                    BYTE byLinkStatus1 = scnet[0x57];

                    BYTE byNetSpeed0 = scnet[0x58];//网络连接速度 10：10M ，100：100M
                    BYTE byNetSpeed1 = scnet[0x59];

                    BYTE byDuplex0 = scnet[0x5a];//网络工作模式 0：HALF，1：FULL
                    BYTE byDuplex1 = scnet[0x5b];

                    BYTE byBurthenOver0 = scnet[0x5c];//网络节点负荷过重报警 0：正常，1：负荷过重
                    BYTE byBurthenOver1 = scnet[0x5d];

                    DWORD dwRunTime = scnet[0x7e] + scnet[0x7f]*0xff + scnet[0x80]*0xff*0xff + scnet[0x81]*0xff*0xff*0xff;//主控制器运行时间(秒级)

                    BYTE byAbnormityNode0 = scnet[0x82];//网络异常节点报警	0：正常，1：存在异常节点
                    BYTE byAbnormityNode1 = scnet[0x83];

                    BYTE byInterCom = scnet[0x84];//总线交错报警 0x80：2->1交错，0x40：1->2交错

                    BYTE byAddrCollision = scnet[0x85];//IP节点冲突报警  0：正常，1：节点冲突

                    BYTE bySntpError = scnet[0x86];//SNTP故障报警  0：正常，1：无时钟服务器

                    BYTE byWorkMode = scnet[0x87];//主控卡工作备用标致 0x00：备用，0x0f：工作

                    //---------------------------------------------------------------------
                    WORD wStatAll0 = scnet[0x5e] + scnet[0x5f]*0xff;//网络平均每秒包数
                    WORD wStatAll1 = scnet[0x60] + scnet[0x61]*0xff;

                    DWORD dwStatALLByte0 = scnet[0x62] + scnet[0x63]*0xff + scnet[0x64]*0xff*0xff + scnet[0x65]*0xff*0xff*0xff;//网络平均每秒字节数
                    DWORD dwStatALLByte1 = scnet[0x66] + scnet[0x67]*0xff + scnet[0x68]*0xff*0xff + scnet[0x69]*0xff*0xff*0xff;

                    WORD wStatBroadcast0 = scnet[0x6a] + scnet[0x6b]*0xff;//网络平均每秒广播包数
                    WORD wStatBroadcast1 = scnet[0x6c] + scnet[0x6d]*0xff;

                    WORD wStatMulticast0 = scnet[0x6e] + scnet[0x6f]*0xff;//网络平均每秒多播包数
                    WORD wStatMulticast1 = scnet[0x70] + scnet[0x71]*0xff;

                    WORD wUnicast0 = scnet[0x72] + scnet[0x73]*0xff;//网络平均每秒点播包数
                    WORD wUnicast1 = scnet[0x74] + scnet[0x75]*0xff;

                    WORD wStatErr0 = scnet[0x76] + scnet[0x77]*0xff;//网络平均每秒错包数
                    WORD wStatErr1 = scnet[0x78] + scnet[0x79]*0xff;

                    WORD wSBUSUnicast0 = scnet[0x7a] + scnet[0x7b]*0xff;//网络SBUS数据每秒包数
                    WORD wSBUSUnicast1 = scnet[0x7c] + scnet[0x7d]*0xff;

                    QString key = ip_src+"_"+diagType;

                    //QMap<QString,QMap<QString,QStringList>> udp1919;
                    if(!udp1919.contains(key)){

                        QMap<QString,QStringList> tmpMap;
                        QStringList tmpTime;
                        QStringList tmpwStatAll0;
                        QStringList tmpwStatAll1;
                        QStringList tmpdwStatALLByte0;
                        QStringList tmpdwStatALLByte1;
                        QStringList tmpwStatBroadcast0;
                        QStringList tmpwStatBroadcast1;
                        QStringList tmpwStatMulticast0;
                        QStringList tmpwStatMulticast1;
                        QStringList tmpwUnicast0;
                        QStringList tmpwUnicast1;
                        QStringList tmpwStatErr0;
                        QStringList tmpwStatErr1;
                        QStringList tmpwSBUSUnicast0;
                        QStringList tmpwSBUSUnicast1;
                        QStringList tmpwdwRunTime;

                        tmpMap.insert("time",tmpTime);          //收到包的时间
                        tmpMap.insert("wStatAll0",tmpwStatAll0);
                        tmpMap.insert("wStatAll1",tmpwStatAll1);
                        tmpMap.insert("dwStatALLByte0",tmpdwStatALLByte0);
                        tmpMap.insert("dwStatALLByte1",tmpdwStatALLByte1);
                        tmpMap.insert("wStatBroadcast0",tmpwStatBroadcast0);
                        tmpMap.insert("wStatBroadcast1",tmpwStatBroadcast1);
                        tmpMap.insert("wStatMulticast0",tmpwStatMulticast0);
                        tmpMap.insert("wStatMulticast1",tmpwStatMulticast1);
                        tmpMap.insert("wUnicast0",tmpwUnicast0);
                        tmpMap.insert("wUnicast1",tmpwUnicast1);
                        tmpMap.insert("wStatErr0",tmpwStatErr0);
                        tmpMap.insert("wStatErr1",tmpwStatErr1);
                        tmpMap.insert("wSBUSUnicast0",tmpwSBUSUnicast0);
                        tmpMap.insert("wSBUSUnicast1",tmpwSBUSUnicast1);
                        tmpMap.insert("dwRunTime",tmpwdwRunTime);   //控制器上发包的时间

                        udp1919.insert(key,tmpMap);

                        emit signal_wireshark(2,"发现"+diagType+"，源IP："+ip_src);

                    }

                    udp1919[key]["time"].append(QString::number(QDateTime::currentDateTime().toMSecsSinceEpoch()));

                    udp1919[key]["wStatAll0"].append(QString::number(wStatAll0));
                    udp1919[key]["wStatAll1"].append(QString::number(wStatAll1));
                    udp1919[key]["dwStatALLByte0"].append(QString::number(dwStatALLByte0));
                    udp1919[key]["dwStatALLByte1"].append(QString::number(dwStatALLByte1));
                    udp1919[key]["wStatBroadcast0"].append(QString::number(wStatBroadcast0));
                    udp1919[key]["wStatBroadcast1"].append(QString::number(wStatBroadcast1));
                    udp1919[key]["wStatMulticast0"].append(QString::number(wStatMulticast0));
                    udp1919[key]["wStatMulticast1"].append(QString::number(wStatMulticast1));
                    udp1919[key]["wUnicast0"].append(QString::number(wUnicast0));
                    udp1919[key]["wUnicast1"].append(QString::number(wUnicast1));
                    udp1919[key]["wStatErr0"].append(QString::number(wStatErr0));
                    udp1919[key]["wStatErr1"].append(QString::number(wStatErr1));
                    udp1919[key]["wSBUSUnicast0"].append(QString::number(wSBUSUnicast0));
                    udp1919[key]["wSBUSUnicast1"].append(QString::number(wSBUSUnicast1));
                    udp1919[key]["dwRunTime"].append(QString::number(dwRunTime));


                    emit signal_net(ip_src+"_"+diagType,byMediaStatus0,byMediaStatus1,byLinkStatus0,byLinkStatus1,byNetSpeed0,byNetSpeed1,byDuplex0,byDuplex1,byBurthenOver0,byBurthenOver1,byAbnormityNode0,byAbnormityNode1,byInterCom,byAddrCollision,bySntpError,byWorkMode);

                }
            }
        }
    }


    emit signal_total(packetType);
}

QStringList mywireshark::getNetcards(){
    pcap_if_t *alldevs=nullptr;
    pcap_if_t *d;
    QStringList result;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        emit signal_wireshark(0,QString("pcap_findalldevs error ")+errbuf);
        pcap_freealldevs(alldevs);
        return result;
    }

    for(d=alldevs;d;d=d->next)
    {
        bpf_u_int32 netp,maskp;
        struct in_addr addr;
        QString net/*, *mask*/;

        pcap_lookupnet(d->name,&netp,&maskp,errbuf);
        addr.s_addr = netp;
        net = inet_ntoa(addr);
//        printf("network: %s\n", net);

//        addr.s_addr = maskp;
//        mask = inet_ntoa(addr);
//        printf("mask: %s\n", mask);

        QString tmp="";

//        tmp = "网段：";

        tmp += d->description;
        tmp += "\t";
        tmp += d->name;
        tmp += "\t";
        tmp += net;

        result.append(tmp);
    }
    pcap_freealldevs(alldevs);
    return result;

}

bool mywireshark::setFilter(QString filter){
    this->filter=filter;
}

int mywireshark::isMulticast(QString inputstr){
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

void mywireshark::setStop(int level){
    this->level=level;
}

int mywireshark::createPcapFile(pcap_dumper_t **dumpfile,pcap_t *adhandle){

    QString tmp;
    tmp=netcardDescript.replace("\\","_").replace("/","_").replace(":","_").replace("*","_").replace("?","_").replace("<","_").replace(">","_").replace("|","_");
    QString filename=tmp+"_"+startPcapTime/*+"_"+QString::number(++index)*/+".pcap";
    QString fullfilename=dirName+"/"+filename;
//    qDebug()<<"createPcapFile:"<<fullfilename;

    *dumpfile = pcap_dump_open(adhandle, fullfilename.toStdString().c_str());

    if(dumpfile==nullptr)
    {
        emit signal_wireshark(0,QString("打开文件失败"));
        active=0;
        return 0;
    }
    return 1;
}










