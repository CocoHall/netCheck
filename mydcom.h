#ifndef MYDCOM_H
#define MYDCOM_H

#include<windows.h>
#include<sddl.h>
#include <lm.h>
#include <iphlpapi.h>
#include <pdh.h>
#include <stdio.h>
class mydcom
{
public:
    mydcom();
    char*  getMachineAccessRestriction();
    char*  getMachineLaunchRestriction();
    char*  getDefaultAccessPermission();
    char*  getDefaultLaunchPermission();
    int  getEnableDCOM();
    int  getEnableDCOMHTTP();
    int  getLegacyAuthenticationLevel();
    int  getLegacyImpersonationLevel();
    char*  getOPCAccess(const char* uuid);
    char*  getOPCLaunch(const char* uuid);

    int  setEnableDCOM(DWORD value);
    int  setEnableDCOMHTTP(DWORD value);
    int  setLegacyAuthenticationLevel(DWORD value);
    int  setLegacyImpersonationLevel(DWORD value);
    int  setDefaultAccessPermission(const char* strSid);
    int  setDefaultLaunchPermission(const char* strSid);
    int  setMachineAccessRestriction(const char* strSid);
    int  setMachineLaunchRestriction(const char* strSid);
    int  setOPCAccess(char* uuid,char* strSid);
    int  setOPCLaunch(char* uuid,char* strSid);
    void  clearOPC(char* uuid);

    char*  getUsernameBySID(const char* SID);
    char*  getSIDByUsername(const char* username);
    char*  getUserName();
    WCHAR*  getGroupName(const WCHAR * username);
    void  myFree();

private:
    unsigned char buffer[4096]={0};
    char name[1024]={0};
    char domain[1024]={0};
    LPSTR lpAPermission[1] = {0};
    WCHAR groupName[1024]={0};
    char* opcdefault="default";
    char* opcnotexist="notexist";


    char* getRestriction(char * keyName);
    char* getDefault(char * keyName);
    int getEnable(char* keyName);
    int getLevel(char * keyName);
    int setEnable(DWORD value,char * keyName);
    int setLevel(DWORD value,char * keyName);
    void deleteRegKey(HKEY hKeyRoot ,char* keyPath,char* keyName);
    int setSID(const char* strSid,const char* keyName);
    char* getOPC(const char* uuid,const char* keyName);
    int setOPC(char* uuid,char* keyName,char* strSid);

};

#endif // MYDCOM_H
