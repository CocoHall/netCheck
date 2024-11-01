#include "myperformance.h"

myperformance::myperformance()
{
    performance_running=0;

    initPhy();
}

void myperformance::judgePhy(unsigned char* NetCfgInstanceId,DWORD Characteristics){
    for(int i=0;i<STRUCTSIZE;i++){
        if(strcmp(stru1[i].AdapterName,(char*)NetCfgInstanceId)==0){
            if((Characteristics & 0x04)==0x04){
                stru1[i].phy=1;
                phyNetCardNum++;
            }else{
                stru1[i].phy=-1;
            }
        }
    }
}

void myperformance::enumNetcard(){
    HKEY hKey = nullptr;
    DWORD dwIndexs = 0;
    TCHAR keyName[MAX_PATH] = { 0 };
    DWORD charLength = 256;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NET_CARD_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        while (RegEnumKeyEx(hKey, dwIndexs, keyName, &charLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            char fullSubKeyPath[MAX_PATH]={0};
            sprintf(fullSubKeyPath,"%s%S",NET_CARD_KEY,keyName);
            long lRetSZ=0,lRetDW=0;
            HKEY subHKey;

            DWORD dwSizeSZ=0,dwSizeDW=0;
            unsigned char dwSZBuffer[128]={0};
            DWORD dwDWResult=0;
            DWORD dwTypeSZ=REG_SZ;
            DWORD dwTypeDW=REG_DWORD;


            lRetSZ = RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullSubKeyPath, 0, KEY_QUERY_VALUE , &subHKey);
            if (ERROR_SUCCESS == lRetSZ)
            {
                dwSizeSZ=sizeof(dwSZBuffer);
                dwSizeDW=sizeof(dwDWResult);
                lRetSZ = RegQueryValueExA(subHKey,"NetCfgInstanceId",NULL,&dwTypeSZ,dwSZBuffer,&dwSizeSZ);
                lRetDW = RegQueryValueExA(subHKey, "Characteristics", NULL, &dwTypeDW, (PBYTE)&dwDWResult, &dwSizeDW);

                RegCloseKey(subHKey);


                if(ERROR_SUCCESS == lRetSZ && ERROR_SUCCESS ==lRetDW){
                    judgePhy(dwSZBuffer,dwDWResult);
                }
            }


            ++dwIndexs;
            charLength = 256;
        }
    }

    if (hKey != NULL)
    {
        RegCloseKey(hKey);
    }
}

void myperformance::initPhy()
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = nullptr;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen;
    pAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
    ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
    {
        pAdapter = pAdapterInfo;
        int i=0;
        while (pAdapter)
        {
            strcpy(stru1[i].AdapterName,pAdapter->AdapterName);
            strcpy(stru1[i].Description,pAdapter->Description);
            stru1[i].phy=-1;
            pAdapter = pAdapter->Next;
            i++;
            if(i>=STRUCTSIZE)break;
        }

    }

    free(pAdapterInfo);
    enumNetcard();
    for(int i=0;i<STRUCTSIZE;i++){
        if(stru1[i].phy==1){
            char description[MAX_PATH]={0};
            strcpy(description,stru1[i].Description);
            for(int k=0;k<strlen(description);k++){
                if(description[k]=='(')description[k]='[';
                if(description[k]==')')description[k]=']';
            }
            if(strlen(phyNetCardNames)!=0){
                strcpy(phyNetCardNames+strlen(phyNetCardNames),",");
            }
            strcpy(phyNetCardNames+strlen(phyNetCardNames),description);
        }
    }


}


int myperformance::initPdh(){
    PDH_STATUS status = PdhOpenQuery(NULL, NULL, &query);
    if (status != ERROR_SUCCESS)return -1;
    int j=-1;
    PdhAddCounterA(query, "\\Processor(_Total)\\% Processor Time", NULL, &(counter[++j]));
    PdhAddCounterA(query, "\\Memory\\Available MBytes", NULL, &(counter[++j]));
    PdhAddCounterA(query, "\\PhysicalDisk(_Total)\\% Disk Read Time", NULL, &(counter[++j]));
    PdhAddCounterA(query, "\\PhysicalDisk(_Total)\\% Disk Write Time", NULL, &(counter[++j]));

    for(int i=0;i<STRUCTSIZE;i++){
        if(stru1[i].phy==1){
            char description[MAX_PATH]={0};
            strcpy(description,stru1[i].Description);
            for(int k=0;k<strlen(description);k++){
                if(description[k]=='(')description[k]='[';
                if(description[k]==')')description[k]=']';
            }

            char dataSource1[MAX_PATH]={0},dataSource2[MAX_PATH]={0},dataSource3[MAX_PATH]={0},dataSource4[MAX_PATH]={0};
            sprintf(dataSource1,"\\Network Interface(%s)\\Bytes Received/sec",description);
            sprintf(dataSource2,"\\Network Interface(%s)\\Bytes Sent/sec",description);
            sprintf(dataSource3,"\\Network Interface(%s)\\Packets Received/sec",description);
            sprintf(dataSource4,"\\Network Interface(%s)\\Packets Sent/sec",description);


            PdhAddCounterA(query, dataSource1, NULL, &(counter[++j]));
            PdhAddCounterA(query, dataSource2, NULL, &(counter[++j]));
            PdhAddCounterA(query, dataSource3, NULL, &(counter[++j]));
            PdhAddCounterA(query, dataSource4, NULL, &(counter[++j]));
            if(j>=4*STRUCTSIZE+OTHER_HCOUNTER-1)break;
        }
    }

    return 0;
}

int myperformance::getPhyNetCardNum(){
    return phyNetCardNum;
}

char* myperformance::getPhyNetCardNames(){
    return phyNetCardNames;
}

void myperformance::collectData(){
    PdhCollectQueryData(query);
}

double myperformance::getPdhValue(int index){
    if(index<0 || index>=phyNetCardNum*4+OTHER_HCOUNTER){
        return -1;
    }
    PDH_FMT_COUNTERVALUE pdhValue;
    DWORD dwValue;
    PdhGetFormattedCounterValue(counter[index], PDH_FMT_DOUBLE, &dwValue, &pdhValue);
    return pdhValue.doubleValue;
}

void myperformance::closePdh(){
    PdhCloseQuery(query);
}

void myperformance::setActive(int flag){
    performance_running=flag;
}

void myperformance::run(){
    setActive(1);
    initPdh();

    emit signal_performance(-1,0);
    while(performance_running==1){
        Sleep(1000);
        collectData();
        for(int i=0;i<OTHER_HCOUNTER+phyNetCardNum*4;i++){
            double value = getPdhValue(i);

//            int index=0;
//            if(i<OTHER_HCOUNTER)index=i;
//            else index = (i-OTHER_HCOUNTER)/4+OTHER_HCOUNTER;
            emit signal_performance(i,value);
        }
        emit signal_performance_updateMaxY();
    }

    closePdh();
}

int myperformance::getActive(){
    return performance_running;
}















