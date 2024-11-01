#include "myprocess.h"

myprocess::myprocess(QObject *parent)
{
    int isok=0;
    TOKEN_PRIVILEGES NewState;
    HANDLE hToken;
    NewState.PrivilegeCount=1;
    NewState.Privileges[0].Attributes=2;
    NewState.Privileges[0].Luid.HighPart=0;
    NewState.Privileges[0].Luid.LowPart=0;
    isok=LookupPrivilegeValue(0,SE_DEBUG_NAME,&NewState.Privileges[0].Luid);
    if(isok){
        isok=OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken);
        if(isok){
            isok=AdjustTokenPrivileges(hToken,0,&NewState,0x10,0,0);
        }
    }
    CloseHandle(hToken);
}

void myprocess::run(){
    while(active){
        HANDLE hProcessSnap;         // 进程快照句柄
        HANDLE hProcess;         // 进程句柄
        PROCESSENTRY32  StcPe32 ;         // 进程快照信息
        StcPe32.dwSize = sizeof(PROCESSENTRY32);
        // 创建进程相关的快照句柄
        hProcessSnap= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if (!hProcessSnap)
        {
            break ;
        }
        // 通过进程快照句柄获取第一个进程信息
        if (!Process32First(hProcessSnap,&StcPe32))
        {
            CloseHandle( hProcessSnap);
            break ;
        }
        QList<QMap<QString,QString>> info;
        // 循环遍历进程信息
        do
        {
            QMap<QString,QString> tmp;
            tmp.insert("PID",QString::number(StcPe32.th32ProcessID));
            tmp.insert("Name",QString::fromWCharArray(StcPe32.szExeFile));
            tmp.insert("Threads",QString::number(StcPe32.cntThreads));
            DWORD dwSessionID = 0;

            if(ProcessIdToSessionId(StcPe32.th32ProcessID, &dwSessionID)){
                tmp.insert("Session",QString::number(dwSessionID));
            }

            hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, StcPe32.th32ProcessID);
            if(hProcess){
                PROCESS_MEMORY_COUNTERS_EX pmc ;
                if(GetProcessMemoryInfo(hProcess,(PROCESS_MEMORY_COUNTERS*)&pmc,sizeof(pmc))){
                    tmp.insert("Memory",QString::number(pmc.WorkingSetSize/1024));
                }

                 HANDLE hNewProcess = NULL;
                 PEB peb;
                 RTL_USER_PROCESS_PARAMETERS upps;
                 HMODULE hModule = LoadLibraryA("Ntdll.dll");
                 typedef NTSTATUS(WINAPI *NtQueryInformationProcessFace)(HANDLE, DWORD, PVOID, ULONG, PULONG);
                 NtQueryInformationProcessFace NtQueryInformationProcess = (NtQueryInformationProcessFace)GetProcAddress(hModule, "NtQueryInformationProcess");

                 if (DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hNewProcess, 0, FALSE, DUPLICATE_SAME_ACCESS))
                 {
                     PROCESS_BASIC_INFORMATION pbi;
                     NTSTATUS isok = NtQueryInformationProcess(hNewProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
                     if (BCRYPT_SUCCESS(isok))
                     {
                         tmp.insert("PPID",QString::number(pbi.InheritedFromUniqueProcessId));
                         if (ReadProcessMemory(hNewProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
                         {
                             if (ReadProcessMemory(hNewProcess, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0)) {
                                 WCHAR *buffer = new WCHAR[upps.CommandLine.Length + 1];
                                 ZeroMemory(buffer, (upps.CommandLine.Length + 1) * sizeof(WCHAR));
                                 ReadProcessMemory(hNewProcess, upps.CommandLine.Buffer, buffer, upps.CommandLine.Length, 0);
                                 tmp.insert("Cmd",QString::fromWCharArray(buffer));
                                 delete[] buffer;

                             }
                         }
                     }
                     CloseHandle(hNewProcess);
                 }
            }

            info.append(tmp);
            CloseHandle(hProcess);

        } while (Process32Next(hProcessSnap,&StcPe32));
        // 关闭句柄退出函数
        CloseHandle(hProcessSnap);

        emit signal_process(info);

        if(saveFlag){
            saveFlag=0;

            QDir dir;
            dir.mkpath(filePath);
            QString fileName="/processInfo.csv";

            QFile file(filePath+fileName);

            if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
            {
//                QMessageBox::warning(this,"错误",QString("打开文件")+file.fileName()+QString("失败"));
                emit signal_processSave(1,QString("打开文件")+file.fileName()+QString("失败"));
                return;
            }
            else
            {
                QTextStream textStream(&file);
                textStream<<QString("名称,进程号,父进程号,会话,线程数,内存(KB),命令行\n");

                for (int i = 0; i < info.size(); ++i)
                {
                    QMap<QString,QString>* node = &(info[i]);
                    textStream<<(*node)["Name"]<<",";
                    textStream<<(*node)["PID"]<<",";
                    textStream<<(*node)["PPID"]<<",";
                    textStream<<(*node)["Session"]<<",";
                    textStream<<(*node)["Threads"]<<",";
                    textStream<<(*node)["Memory"]<<",";
                    textStream<<(*node)["Cmd"]<<"\n";

                }

                file.close();
//                QMessageBox::information(this,"提示",QString("文件保存至")+file.fileName());
                emit signal_processSave(0,QString("文件保存至")+file.fileName());
            }
        }
        Sleep(1000);
    }

    active=0;
    return ;

}

void myprocess::save(QString path){
    filePath=path;
    saveFlag=1;
}
