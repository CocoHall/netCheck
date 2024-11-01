#include "mydcom.h"

mydcom::mydcom()
{

}

char* mydcom::getRestriction(char * keyName){
     long lRet=0;
     HKEY hKey;

     DWORD dwSize=0;
     memset(buffer,0,sizeof(buffer));

     lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DCOM", 0, KEY_QUERY_VALUE , &hKey);
     if (ERROR_SUCCESS == lRet)
     {
          dwSize=sizeof(buffer);
          lRet=RegQueryValueExA(hKey,keyName,nullptr,nullptr,buffer,&dwSize);
          RegCloseKey(hKey);
          if(ERROR_SUCCESS == lRet){

                return (char*)buffer;
          }
     }

     lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_QUERY_VALUE , &hKey);
     if (ERROR_SUCCESS == lRet)
     {
          dwSize=sizeof(buffer);
          lRet=RegQueryValueExA(hKey,keyName,nullptr,nullptr,buffer,&dwSize);
          RegCloseKey(hKey);
          if(ERROR_SUCCESS == lRet){
                ConvertSecurityDescriptorToStringSecurityDescriptorA((PSECURITY_DESCRIPTOR)buffer, SECURITY_DESCRIPTOR_REVISION, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, lpAPermission, nullptr);
                return (char*)lpAPermission[0];
          }

     }
     return NULL;//增加默认DCOM设置
}

char* mydcom::getDefault(char * keyName){
     long lRet=0;
     HKEY hKey;

     DWORD dwSize=0;
     memset(buffer,0,sizeof(buffer));

     lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_QUERY_VALUE , &hKey);
     if (ERROR_SUCCESS == lRet)
     {
          dwSize=sizeof(buffer);
          lRet=RegQueryValueExA(hKey,keyName,nullptr,nullptr,buffer,&dwSize);
          RegCloseKey(hKey);
          if(ERROR_SUCCESS == lRet){
                ConvertSecurityDescriptorToStringSecurityDescriptorA((PSECURITY_DESCRIPTOR)buffer, SECURITY_DESCRIPTOR_REVISION, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, lpAPermission, NULL);
                return (char*)lpAPermission[0];
          }

     }
     return nullptr;//增加默认DCOM设置
}

char* mydcom::getMachineAccessRestriction(){
     char * result = getRestriction("MachineAccessRestriction");
     if(result==nullptr)return "O:BAG:BAD:(A;;CCDCLC;;;WD)(A;;CCDC;;;AN)(A;;CCDCLC;;;S-1-5-32-562)(A;;CCDCLC;;;LU)(A;;CCDC;;;AC)(A;;CCDC;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)";
     return result;
}

char* mydcom::getMachineLaunchRestriction(){
     char * result = getRestriction("MachineLaunchRestriction");
     if(result==nullptr)return "O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)";
     return result;
}

char* mydcom::getDefaultAccessPermission(){
     char * result = getDefault("DefaultAccessPermission");
     if(result==nullptr)return "O:BAG:BAD:(A;;CCDCLC;;;PS)(A;;CCDC;;;SY)(A;;CCDCLC;;;BA)";
     return result;
}

char* mydcom::getDefaultLaunchPermission(){
     char * result =  getDefault("DefaultLaunchPermission");
     if(result==nullptr)return "O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)";
     return result;
}

int mydcom::getEnable(char* keyName){
     long lRet=0;
     HKEY hKey;

     DWORD dwSize=0;
     unsigned char buffer[16]={0};
     DWORD dwType=REG_SZ;

     lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_QUERY_VALUE , &hKey);
     if (ERROR_SUCCESS == lRet)
     {
          dwSize=sizeof(buffer);
          lRet=RegQueryValueExA(hKey,keyName,nullptr,&dwType,buffer,&dwSize);
          RegCloseKey(hKey);
          if(ERROR_SUCCESS == lRet){
                if(strcmp((char*)buffer,"Y")==0){
                     return 1;
                }else{
                     return 0;
                }
          }
     }
     return 0;
}

int mydcom::getEnableDCOM(){
     return getEnable("EnableDCOM");
}

int mydcom::getEnableDCOMHTTP(){
     return getEnable("EnableDCOMHTTP");
}

int mydcom::getLevel(char * keyName){
     long lRet=0;
     HKEY hKey;

     DWORD dwSize=0;
     DWORD dwResult=2;
     DWORD dwType=REG_DWORD;

     lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_QUERY_VALUE , &hKey);
     if (ERROR_SUCCESS == lRet)
     {
          dwSize=sizeof(dwResult);
          lRet=RegQueryValueExA(hKey,keyName,NULL,&dwType,(PBYTE)&dwResult,&dwSize);
          RegCloseKey(hKey);
          return dwResult;
     }
     return dwResult;
}

//0:默认     1:无     2:连接(win10默认)     3:调用     4:数据包    5:数据包完整性     6:数据包保密性
int mydcom::getLegacyAuthenticationLevel(){
     return getLevel("LegacyAuthenticationLevel");
}

//1:匿名     2:标识(win10默认)     3:模拟     4:委派
int mydcom::getLegacyImpersonationLevel(){
     return getLevel("LegacyImpersonationLevel");
}

int mydcom::setEnable(DWORD value,char * keyName){
     HKEY hKey;

     LONG lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_WRITE , &hKey);
     if (ERROR_SUCCESS != lRet)
     {
          return -1;
     }

     switch(value){
          case 1:
                {
                     const char *pchrNameY = "Y";
                     lRet = RegSetValueExA(hKey, keyName, NULL, REG_SZ, (LPBYTE)pchrNameY, strlen(pchrNameY) * sizeof(char) + 1);
                }
                break;

          case 0:
                {
                     const char *pchrNameN = "N";
                     lRet = RegSetValueExA(hKey, keyName, NULL, REG_SZ, (LPBYTE)pchrNameN, strlen(pchrNameN) * sizeof(char) + 1);
                }
                break;
          default :
                lRet=-1;
                break;
     }

     RegCloseKey(hKey);
     return lRet;
}

int mydcom::setEnableDCOM(DWORD value){
     return setEnable(value,"EnableDCOM");
}

int mydcom::setEnableDCOMHTTP(DWORD value){
     return setEnable(value,"EnableDCOMHTTP");
}

int mydcom::setLevel(DWORD value,char * keyName){
     HKEY hKey;

     LONG lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_WRITE , &hKey);
     if (ERROR_SUCCESS != lRet)
     {
          return -1;
     }

     lRet = RegSetValueExA(hKey, keyName, NULL, REG_DWORD, (CONST BYTE*)&value, sizeof(DWORD));

     RegCloseKey(hKey);
     return lRet;
}

int mydcom::setLegacyAuthenticationLevel(DWORD value){
     return setLevel(value,"LegacyAuthenticationLevel");
}

int mydcom::setLegacyImpersonationLevel(DWORD value){
     return setLevel(value,"LegacyImpersonationLevel");
}

void mydcom::deleteRegKey(HKEY hKeyRoot ,char* keyPath,char* keyName){
     HKEY hKEY;
     LONG lRet = 0;
     lRet = RegOpenKeyExA(hKeyRoot, keyPath, 0, KEY_SET_VALUE, &hKEY);
     if(ERROR_SUCCESS == lRet)
     {
          RegDeleteValueA(hKEY, keyName);
     }
     RegCloseKey(hKEY);
}


int mydcom::setSID(const char* strSid,const char * keyName){

     PSECURITY_DESCRIPTOR vSecurityDescriptor1;
     ULONG  vNeedBytes1 = 0;
     ConvertStringSecurityDescriptorToSecurityDescriptorA(strSid, 1, &vSecurityDescriptor1, &vNeedBytes1);
     if (vNeedBytes1 < 1)return -1;

     HKEY hKey;
     LONG lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Ole", 0, KEY_WRITE , &hKey);
     if (ERROR_SUCCESS != lRet)
     {
          return -1;
     }

     lRet = RegSetValueExA(hKey, keyName, NULL, REG_BINARY, (LPBYTE)vSecurityDescriptor1, vNeedBytes1);

     RegCloseKey(hKey);
     return lRet;
}


int mydcom::setDefaultAccessPermission(const char* strSid){
     return setSID(strSid,"DefaultAccessPermission");
}

int mydcom::setDefaultLaunchPermission(const char* strSid){
     return setSID(strSid,"DefaultLaunchPermission");
}

int mydcom::setMachineAccessRestriction(const char* strSid){
     deleteRegKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DCOM","MachineAccessRestriction");
     return setSID(strSid,"MachineAccessRestriction");
}

int mydcom::setMachineLaunchRestriction(const char* strSid){
     deleteRegKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DCOM","MachineLaunchRestriction");
     return setSID(strSid,"MachineLaunchRestriction");
}

char* mydcom::getUsernameBySID(const char* strSid){
     LONG lRet=0;
     PSID pIntegritySid = NULL;
     lRet = ConvertStringSidToSidA(strSid,&pIntegritySid);
     DWORD cchName=sizeof(name);
     DWORD ccDomain=sizeof(domain);

     memset(name,0,cchName);
     memset(domain,0,ccDomain);
     DWORD peUse=0;
     LookupAccountSidA("localhost",pIntegritySid,name,&cchName,domain,&ccDomain,(PSID_NAME_USE)&peUse);
     LocalFree(pIntegritySid);
     return name;
}

char* mydcom::getSIDByUsername(const char* username){
     SID_NAME_USE    snuType;

     DWORD             ccDomain         = sizeof(domain);
     PSID            pUserSID         = nullptr;
     DWORD             ccUserSID        = 0;

     memset(domain,0,ccDomain);
     memset(name,0,sizeof(name));
     LPSTR strSid=nullptr;
     int ret =0;

     ret = LookupAccountNameA(nullptr, username,pUserSID, &ccUserSID, domain, &ccDomain, &snuType);
     if(ccUserSID<=0){
        memcpy(name,username,strlen(username));
        return name;
     }
     pUserSID=malloc(ccUserSID);
     LookupAccountNameA(nullptr, username,pUserSID, &ccUserSID, domain, &ccDomain, &snuType);
     ConvertSidToStringSidA(pUserSID,&strSid);

     memcpy(name,strSid,strlen(strSid));

     LocalFree(strSid);
     free(pUserSID);
     // if(strlen(name)==0)memcpy(name,username,strlen(username));
     return name;
}

char* mydcom::getOPC(const char* uuid,const char* keyName){
     long lRet=0;
     HKEY hKey;

     DWORD dwSize=0;
     memset(buffer,0,sizeof(buffer));

     char keyPath[1024]={0};
     strcpy(keyPath,"AppID\\");
     strcpy(keyPath+strlen(keyPath),uuid);

     lRet = RegOpenKeyExA(HKEY_CLASSES_ROOT, keyPath, 0, KEY_QUERY_VALUE , &hKey);

     if (ERROR_SUCCESS == lRet)
     {

          dwSize=sizeof(buffer);
          lRet=RegQueryValueExA(hKey,keyName,nullptr,nullptr,buffer,&dwSize);
          RegCloseKey(hKey);
          if(ERROR_SUCCESS == lRet){
                ConvertSecurityDescriptorToStringSecurityDescriptorA((PSECURITY_DESCRIPTOR)buffer, SECURITY_DESCRIPTOR_REVISION, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, lpAPermission, nullptr);
                return (char*)lpAPermission[0];
          }
          return opcdefault;//默认
     }
     return opcnotexist;//不存在
}

char* mydcom::getOPCAccess(const char* uuid){
     return getOPC(uuid,"AccessPermission");
}

char* mydcom::getOPCLaunch(const char* uuid){
     return getOPC(uuid,"LaunchPermission");
}

void mydcom::clearOPC(char* uuid){
    char keyPath[1024]={0};
    strcpy(keyPath,"AppID\\");
    strcpy(keyPath+strlen(keyPath),uuid);
    deleteRegKey(HKEY_CLASSES_ROOT,keyPath,"AccessPermission");
    deleteRegKey(HKEY_CLASSES_ROOT,keyPath,"LaunchPermission");
}

int mydcom::setOPC(char* uuid,char* keyName,char* strSid){
     char keyPath[1024]={0};
     strcpy(keyPath,"AppID\\");
     strcpy(keyPath+strlen(keyPath),uuid);

     PSECURITY_DESCRIPTOR vSecurityDescriptor1;
     ULONG  vNeedBytes1 = 0;
     ConvertStringSecurityDescriptorToSecurityDescriptorA(strSid, 1, &vSecurityDescriptor1, &vNeedBytes1);
     if (vNeedBytes1 < 1)return -1;

     HKEY hKey;
     LONG lRet = RegOpenKeyExA(HKEY_CLASSES_ROOT, keyPath, 0, KEY_WRITE , &hKey);
     if (ERROR_SUCCESS != lRet)
     {
          return -1;
     }

     lRet = RegSetValueExA(hKey, keyName, NULL, REG_BINARY, (LPBYTE)vSecurityDescriptor1, vNeedBytes1);

     RegCloseKey(hKey);
     return lRet;
}

int mydcom::setOPCAccess(char* uuid,char* strSid){
     return setOPC(uuid,"AccessPermission",strSid);
}

int mydcom::setOPCLaunch(char* uuid,char* strSid){
     return setOPC(uuid,"LaunchPermission",strSid);
}

char* mydcom::getUserName(){
     DWORD pcbBuffer=sizeof(name);
     memset(name,0,sizeof(name));
     GetUserNameA(name,&pcbBuffer);
     return name;
}

void mydcom::myFree(){
     LocalFree(lpAPermission[0]);
     lpAPermission[0]=NULL;
}


WCHAR* mydcom::getGroupName(const WCHAR * username){
   LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
   DWORD dwLevel = 0;
   DWORD dwFlags = LG_INCLUDE_INDIRECT ;
   DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
   DWORD dwEntriesRead = 0;
   DWORD dwTotalEntries = 0;
   NET_API_STATUS nStatus;

   nStatus = NetUserGetLocalGroups(NULL,
                                   username,
                                   dwLevel,
                                   dwFlags,
                                   (LPBYTE *) &pBuf,
                                   dwPrefMaxLen,
                                   &dwEntriesRead,
                                   &dwTotalEntries);

   memset(groupName,0,sizeof(groupName));

   if (nStatus == NERR_Success)
   {
      LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
      DWORD i;

      if ((pTmpBuf = pBuf) != NULL)
      {

         for (i = 0; i < dwEntriesRead; i++)
         {

            if (pTmpBuf == NULL)
            {
               break;
            }
            wcsncpy(groupName+wcslen(groupName),pTmpBuf->lgrui0_name,wcslen(pTmpBuf->lgrui0_name));
            wcsncpy(groupName+wcslen(groupName),L",",1);
            pTmpBuf++;
         }
      }

   }

   if (pBuf != NULL)
      NetApiBufferFree(pBuf);

   return groupName;
}

