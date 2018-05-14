// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <windows.h>
#include <tlhelp32.h>  
#include <atlstr.h>    
#include <locale.h>
#include <process.h>
#include <winuser.h>
#include <Psapi.h>
#include <ntstatus.h> 
#include <vector>
#include <Strsafe.h>
#include <WinSock2.h>
#include <WinInet.h>
#include <WS2tcpip.h>
#include <time.h>
#include "easyhook.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif

using namespace std;

typedef struct _rule
{
	LONG StartTime;
	LONG EndTime;
	char sActionName[20];
	char sTriggleExpr[100];
}RULE_STRUCT, *PRULE_STRUCT;

enum PacketCommand /*: unsigned char*/
{
	PACKET_COMMAND_NONE = -1,
	PACKET_COMMAND_REQUEST_RULE = 0,
	PACKET_COMMAND_REQUEST_CONFIG_FILE = 1,
	PACKET_COMMAND_POST_MONITOR_INFO = 2,
	PACKET_COMMAND_REQUEST_RECONNECT = 3,
	PACKET_COMMAND_REQUEST_EXPIRED_TIME = 4,
	PACKET_COMMAND_REQUEST_LOGIN = 5,
	PACKET_COMMAND_REQUEST_RELOGIN = 6,
	PACKET_COMMAND_REQUEST_UPDATE_RULE = 7,
	PACKET_CLIENT_COMMAND_REQUEST_QQ_RULE = 8,
	PACKET_CLIENT_COMMAND_REQUEST_WECHAT_RULE = 9,
	PACKET_CLIENT_COMMAND_REQUEST_FETION_RULE = 10,
	PACKET_CLIENT_COMMAND_REQUEST_USB_RULE = 11,
	PACKET_CLIENT_COMMAND_REQUEST_WEB_RULE = 12,
	PACKET_CLIENT_COMMAND_REQUEST_NETDISK_RULE = 13,
	PACKET_CLIENT_COMMAND_REQUEST_FOXMAIL_RULE = 14,
	PACKET_CLIENT_COMMAND_REQUEST_UPDATE_RULE = 15,
	PACKET_CLIENT_COMMAND_REQUEST_RECONNECT = 16,
	PACKET_CLIENT_COMMAND_REQUEST_LOGIN = 17,
	PACKET_CLIENT_COMMAND_REQUEST_RELOGIN = 18,
	PACKET_CLIENT_COMMAND_POST_QQ_INFO = 19,
	PACKET_CLIENT_COMMAND_POST_WECHAT_INFO = 20,
	PACKET_CLIENT_COMMAND_POST_FETION_INFO = 21,
	PACKET_CLIENT_COMMAND_POST_USB_INFO = 22,
	PACKET_CLIENT_COMMAND_POST_WEB_INFO = 23,
	PACKET_CLIENT_COMMAND_POST_NETDISK_INFO = 24,
	PACKET_CLIENT_COMMAND_POST_FOXMAIL_INFO = 25,
	PACKET_CLIENT_COMMAND_REQUEST_START_RECORD_DESKTOP = 26
};

enum PacketAction /*: unsigned char*/
{
	PACKET_ACTION_NONE = 0,
	PACKET_ACTION_GET = 1,
	PACKET_ACTION_POST = 2,
	PACKET_ACTION_REPLY = 3,
	PACKET_ACTION_UPDATE = 4,
	PACKET_ACTION_ACCEPT = 5,
	PACKET_ACTION_REMOVE = 6,
	PACKET_ACTION_AGREE = 7,
	PACKET_ACTION_CREATE = 8,
	PACKET_ACTION_ADD = 9
};

enum PacketEncryption /* : unsigned char*/
{
	PACKET_ENCRYPTION_NONE = 0,
	PACKET_ENCRYPTION_MD5 = 1,
	PACKET_ENCRYPTION_RSA = 2,
	PACKET_ENCRYPTION_DES = 3,
	PACKET_ENCRYPTION_SHA = 5,
	PACKET_ENCRYPTION_AES = 4
};

enum PacketCheck/* : unsigned char*/
{
	PACKET_CHECK_NONE = 0,
	PACKET_CHECK_MD5 = 1,
	PACKET_CHECK_CRC = 2,
};

typedef struct qq_tag
{
	UINT nLocalIPLength;
	UINT nSenderQQLength;
	UINT nReceiverIPLength;
	UINT nSendFilePathLength;
	INT  nTriggleTime;
	UINT nHostName;
	// CHAR sLocalIP[50];
	// CHAR sSenderQQ[50];
	// CHAR sReceiverIP[50];
	// CHAR sSendFilePath[50];
}qq;

typedef struct wechat_tag
{
	UINT nLocalIPLength;
	UINT nReceiverIPLength;
	UINT nSendFilePathLength;
	INT  nTriggleTime;
	UINT nHostName;
	// CHAR sLocalIP[50];
	// CHAR sReceiverIP[50];
	// CHAR sSendFilePath[50];
}wechat;

typedef struct fetion_tag
{
	UINT nLocalIPLength;
	UINT nReceiverIPLength;
	UINT nSendFilePathLength;
	INT  nTriggleTime;
	UINT nHostName;
	// CHAR sLocalIP[50];
	// CHAR sRemoteIP[50];
	// CHAR sSendFilePath[50];
}fetion;

typedef struct usb_tag
{
	bool bUsbInsert;
	UINT nCopyFileLength;
	INT  nTriggleTime;
	// CHAR sCopyFile[50];
}usb;

typedef struct foxmail_tag
{
	UINT nUserMailAddressLength;
	UINT nReceiverMailAddressLength;
	UINT nAttachFilePathLenth;
	INT  nTriggleTime;
	// CHAR sUserMailAddress[50];
	// CHAR sReceiverMailAddress[50];
	// CHAR sAttachFilePath[50];
}foxmail;

typedef struct web_tag
{
	UINT nAccessURLLength;
	INT  nTriggleTime;
	// CHAR sAccessURL[50];
}web;

typedef struct netdisk_tag
{
	UINT nNetDiskNameLenth;
	UINT nNetDiskNameLength;
	INT  nTriggleTime;
	// CHAR sUploadFilePath[50];
	// CHAR sUploadFilePath[50];
}netdisk;

//client
typedef struct packet_client_header
{
	INT command;
	INT action;
	INT check;
	INT pkgSize;
	INT pkgTag;
	union pkgInfoTag
	{
		qq pkg_qq;
		wechat pkg_wechat;
		fetion pkg_fetion;
		usb pkg_usb;
		foxmail pkg_foxmail;
		web pkg_web;
		netdisk pkg_netdisk;
	}pkgInfo;
}PKG_CLIENT_HEAD_STRUCT, *PPKG_CLIENT_HEAD_STRUCT;

//server
typedef struct packet_header
{
	INT command;
	INT action;
	INT check;
	/*PacketCommand command;
	PacketAction action;
	PacketCheck check;*/
	INT pkgSize;
	INT pkgTag;
}PKG_HEAD_STRUCT, *PPKG_HEAD_STRUCT;

typedef struct packet_body
{
	CHAR data[1];
}PKG_BODY_STRUCT, *PPKG_BODY_STRUCT;

#pragma data_seg("sharedata")  
HHOOK glhHook = NULL;  //钩子句柄。

HINSTANCE glhInstance = NULL;  //DLL实例句柄
#pragma data_seg()  
#pragma comment(linker,"/SECTION:sharedata,RWS") 
HHOOK hook = NULL;
HMODULE hM;
HANDLE hExitEvent;
SOCKET sockfd;
//HANDLE hHandle = NULL;

HANDLE hTimerQueue;
HANDLE hTimer;
HANDLE g_hHandle = NULL;
static volatile LONG  g_nReady = 0;
//char g_sFilePath[100] = {0};

LONG StartTime;
LONG EndTime;
char sActionName[20] = { 0 };
char sTriggleExpr[100] = { 0 };
char sObjInstallPath[100] = { 0 };

char g_sHost[50] = {0};
char g_sSenderIP[20] = {0};
char g_sReceiverIP[20] = {0};
char g_sSenderNum[20] = {0};
time_t g_tTriggleTime;
static INT nSame = 0;

TCHAR sWindir[100] = { 0 };
TCHAR sUserprofiledir[100] = { 0 };
TCHAR sAppdatadir[100] = { 0 };
TCHAR sProgramfilesdir[100] = { 0 };
TCHAR sCommonprogramfilesdir[100] = { 0 };
TCHAR sAllusersprofiledir[100] = { 0 };
TCHAR sTempdir[100] = { 0 };

string path1;
string path2;
string path3;
string path4;
string path5;
string path6;
string path7;
string path8;
string path9;
static int icount = 1;
#define BUFSIZE 512
TCHAR pszFilename[MAX_PATH + 1];

int WSAAPI Myrecv(
	_In_  SOCKET s,
	_Out_writes_bytes_(len) const char FAR *buf,
	_In_  int    len,
	_In_  int    flags
	);

typedef int (WSAAPI *ptrMyrecv)(
	_In_  SOCKET s,
	_Out_writes_bytes_(len) const char FAR *buf,
	_In_  int    len,
	_In_  int    flags
	);

int WSAAPI Mysend(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags
	);

typedef int (WSAAPI *ptrMysend)(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags
	);

BOOL WINAPI MyWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

typedef BOOL(WINAPI *ptrMyWriteFile)(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

int WSAAPI Mysendto(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags,
	_In_reads_bytes_(tolen) const struct sockaddr FAR * to,
	_In_ int tolen
	);

typedef int(WSAAPI *ptrMysendto)(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags,
	_In_reads_bytes_(tolen) const struct sockaddr FAR * to,
	_In_ int tolen
	);

HANDLE WINAPI MyCreateFileW(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	);

typedef HANDLE(WINAPI *ptrCreateFileW)(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	);

//extern ptrCreateFileW realCreateFileW;

HANDLE WINAPI MyCreateFileA(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	);

typedef HANDLE(WINAPI *ptrCreateFileA)(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	);

BOOL WINAPI MyReadFile(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

typedef BOOL (WINAPI *ptrReadFile)(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

BOOL WINAPI myCreateProcessA(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *ptrCreateProcessA)(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);
//ptrCreateProcessA realCreateProcessA;

BOOL WINAPI myCreateProcessW(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *ptrCreateProcessW)(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);

//WINBASEAPI
//HANDLE
//WINAPI
//CreateFileW(
//_In_ LPCWSTR lpFileName,
//_In_ DWORD dwDesiredAccess,
//_In_ DWORD dwShareMode,
//_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//_In_ DWORD dwCreationDisposition,
//_In_ DWORD dwFlagsAndAttributes,
//_In_opt_ HANDLE hTemplateFile
//);

ptrMyrecv realrecv = NULL;
ptrMysend realsend = NULL;
ptrMyWriteFile realWriteFile = NULL;
ptrMysendto realsendto = NULL;
ptrCreateProcessA realCreateProcessA = NULL;
ptrCreateProcessW realCreateProcessW = NULL;

ptrReadFile realReadFile = NULL;
ptrCreateFileW realCreateFileW = NULL;
ptrCreateFileA realCreateFileA = NULL;
HMODULE                 hKernel32 = NULL;
TRACED_HOOK_HANDLE hHookrecv = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHooksend = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHookWriteFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHookReadFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHooksendto = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateFileW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookCreateFileA = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHookCreateProcessW = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE hHookCreateProcessA = new HOOK_TRACE_INFO();
//HOOK_TRACE_INFO hHookCreateProcessW = { NULL }; // keep track of our hook
//HOOK_TRACE_INFO hHookCreateProcessA = { NULL }; // keep track of our hook
NTSTATUS                statue;
ULONG                   Hookrecv_ACLEntries[1] = { 0 };
ULONG                   Hooksend_ACLEntries[1] = { 0 };
ULONG                   HookWriteFile_ACLEntries[1] = { 0 };
ULONG                   Hooksendto_ACLEntries[1] = { 0 };
ULONG                   HookCreateFileW_ACLEntries[1] = { 0 };
ULONG                   HookCreateFileA_ACLEntries[1] = { 0 };
ULONG HookCreateProcessW_ACLEntries[1] = { 0 };
ULONG HookCreateProcessA_ACLEntries[1] = { 0 };
ULONG                   HookReadFile_ACLEntries[1] = { 0 };

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);
extern "C" void __declspec(dllexport) __stdcall mydll();
extern "C" LRESULT __declspec(dllexport) __stdcall KeyProc(
	_In_ int    code,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	);

LRESULT __declspec(dllimport) __stdcall KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

void DoHook();
int PrepareRealApiEntry();

LRESULT CALLBACK KeyProc(
	_In_ int    code,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	)
{
	cout << "code" << code << endl;
	cout << "wParam" << wParam << endl;
	cout << "lParam" << lParam << endl;
	if ((wParam == VK_BACK) || (wParam == VK_TAB) || (wParam == VK_RETURN) || (wParam >= 0x20) && (wParam <= 0x100))
	{
		MessageBoxA(NULL, "1", "1 ", 0);
		//PostMessage(hWndServer, UWN_KEYSTROKE, wParam, lParam);
	}
	/*PCWPSTRUCT pcs = NULL;
	pcs = (PCWPSTRUCT)lParam;
	if (pcs->message == WM_RBUTTONUP)
	{
	MessageBoxA(NULL, "WM_RBUTTONUP", "WM_RBUTTONUP ", 0);
	}
	if (((DWORD)lParam & 0x40000000) && (HC_ACTION == code)){
	PCWPSTRUCT pcs = NULL;
	pcs = (PCWPSTRUCT)lParam;
	if ((pcs != NULL) && (HC_ACTION == code)) {
	if (pcs->message == WM_RBUTTONUP)
	{
	MessageBoxA(NULL, "WM_RBUTTONUP", "WM_RBUTTONUP ", 0);
	}
	}
	}*/
	return TRUE;
}

void __stdcall mydll()
{
	MessageBoxA(NULL, "hello", "hello ", 0);
}

//LRESULT CALLBACK myProc(
//	_In_ int    nCode,
//	_In_ WPARAM wParam,
//	_In_ LPARAM lParam
//	)
LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	//StringCchPrintf();
	//PMSG
	//MessageBoxA(NULL, "1", "1 ", 0);
	/*tagMSG *msg;
	msg = (tagMSG*)lParam;*/
	PCWPSTRUCT pcs = NULL;
	pcs = (PCWPSTRUCT)lParam;
	//if (((DWORD)lParam & 0x40000000) && (HC_ACTION == nCode))
	if (nCode >= HC_ACTION)
	{
		if (pcs->message == WM_MOUSEMOVE) {
			MessageBoxA(NULL, "987", "987", 0);
		}
		if (wParam > 0) {
			MessageBoxA(NULL, "sdf", "sdf", 0);
		}
		//if ((wParam == VK_BACK) || (wParam == VK_TAB) || (wParam == VK_RETURN) || (wParam >= 0x20) && (wParam <= 0x100))
		//{
		//	MessageBoxA(NULL, "1", "1 ", 0);
		//	//PostMessage(hWndServer, UWN_KEYSTROKE, wParam, lParam);
		//}
	}
	//PCWPSTRUCT pcs = NULL;
	//pcs = (PCWPSTRUCT)lParam;
	//if (pcs && pcs->hwnd != NULL && code == HC_ACTION)
	//{
	//	//MessageBoxA(NULL, "1", "1 ", 0);
	//	if (pcs->message == WM_MOUSEMOVE)
	//	{
	//		MessageBoxA(NULL, "SetWindowsHookEx", "warning ", 0);
	//	}

	//	//MessageBoxA(NULL, "1", "1 ", 0);
	//	//TCHAR szClass[256];
	//	//GetClassName(pcs->hwnd, szClass, 255);//获得拦截的窗口类名。
	//	//if (wcscmp(szClass, _T("Notepad")) == 0)
	//	//{
	//	//	MessageBoxA(NULL, "1", "1 ", 0);
	//	//	if (pcs->message == WM_LBUTTONUP)
	//	//	{
	//	//		MessageBoxA(NULL, "SetWindowsHookEx", "warning ", 0);
	//	//	}
	//	//}
	//}
	return CallNextHookEx(hook, nCode, wParam, lParam);//继续传递消息。
}
BOOL CALLBACK noteProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
	)
{
	//MessageBoxA(NULL, "1NativeInjectionEntryPoint", "1NativeInjectionEntryPoint ", 0);
	DWORD lpdwProcessId = NULL;
	DWORD ThreadId = GetWindowThreadProcessId(hwnd, &lpdwProcessId);
	//printf("thread id:%ld, process id:%ld\n", ThreadId, lpdwProcessId);
	if (lParam == lpdwProcessId) {
		//MessageBoxA(NULL, "2", "2 ", 0);
		/*TCHAR szWndowText[MAX_PATH] = { 0 };
		TCHAR szClassName[MAX_PATH] = { 0 };
		GetWindowText(hwnd, szWndowText, MAX_PATH);
		GetClassName(hwnd, szClassName, MAX_PATH);
		wprintf(_T("nodepad windows text:%s\n"), szWndowText);
		wprintf(L"nodepad class name:%s\n", szClassName);*/
		/*GetModuleFileName();
		GetModuleHandle();*/
		//HMODULE DllModule = LoadLibrary(L"E:\\tu\\vs_project\\hook_dll\\x64\\Release\\hook_dll.dll");
		//HMODULE	DllModule = LoadLibrary(L"E:\\tu\\vs_project\\hook_dll\\Release\\hook_dll.dll");
		////FARPROC FunctionAddress = GetProcAddress(DllModule, "KeyboardProc");
		//HOOKPROC addr = (HOOKPROC)GetProcAddress(DllModule, "KeyboardProc");

		hook = SetWindowsHookEx(WH_GETMESSAGE, CallWndProc, glhInstance, ThreadId);
		//HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, DllModule, ThreadId);
		//HHOOK handle = SetWindowsHookEx(WH_CALLWNDPROC, addr, glhInstance, ThreadId);
		//hook = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, ThreadId);
		if (hook == NULL) {
			MessageBoxA(NULL, "678", "678", 0);
			cout << "inject fail" << endl;
			return FALSE;
		}
		//MessageBoxA(NULL, "inject sucess", "inject sucess", 0);
		//return FALSE;
		cout << "inject sucess" << endl;
	}
	return TRUE;
}
BOOL CALLBACK myEnumWindowsProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
	)
{

}

BOOL GrantPriviledge(IN PWCHAR PriviledgeName)
{
	TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
	DWORD			 dwReturnLength = sizeof(OldPrivileges);
	HANDLE			 TokenHandle = NULL;
	LUID			 uID;

	// 打开权限令牌
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
		{
			return FALSE;
		}
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
		{
			return FALSE;
		}
	}

	if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID))		// 通过权限名称查找uID
	{
		CloseHandle(TokenHandle);
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = uID;

	// 在这里我们进行调整权限
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
	{
		CloseHandle(TokenHandle);
		return FALSE;
	}

	// 成功了
	CloseHandle(TokenHandle);
	return TRUE;
}

BOOL GetProcessIdByProcessImageName(IN WCHAR* wzProcessImageName, OUT UINT32* TargetProcessId)
{
	HANDLE			ProcessSnapshotHandle = NULL;
	PROCESSENTRY32	ProcessEntry32 = { 0 };

	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);		// 初始化PROCESSENTRY32结构

	ProcessSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	// 给系统所有的进程快照

	if (ProcessSnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	Process32First(ProcessSnapshotHandle, &ProcessEntry32);		// 找到第一个
	do
	{
		if (lstrcmpi(ProcessEntry32.szExeFile, wzProcessImageName) == 0)		// 不区分大小写
		{
			*TargetProcessId = ProcessEntry32.th32ProcessID;
			break;
		}
	} while (Process32Next(ProcessSnapshotHandle, &ProcessEntry32));

	CloseHandle(ProcessSnapshotHandle);
	ProcessSnapshotHandle = NULL;

	if (*TargetProcessId == 0)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL GetThreadIdByProcessId(UINT32 ProcessId, vector<UINT32>& ThreadIdVector)
{
	HANDLE			ThreadSnapshotHandle = NULL;
	THREADENTRY32	ThreadEntry32 = { 0 };

	ThreadEntry32.dwSize = sizeof(THREADENTRY32);

	ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (ThreadSnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	Thread32First(ThreadSnapshotHandle, &ThreadEntry32);
	do
	{
		if (ThreadEntry32.th32OwnerProcessID == ProcessId)
		{
			ThreadIdVector.emplace_back(ThreadEntry32.th32ThreadID);		// 把该进程的所有线程id压入模板
		}
	} while (Thread32Next(ThreadSnapshotHandle, &ThreadEntry32));

	CloseHandle(ThreadSnapshotHandle);
	ThreadSnapshotHandle = NULL;
	return TRUE;
}

BOOL Inject(IN UINT32 ThreadId, OUT HHOOK& HookHandle)
{
	//HMODULE	DllModule = LoadLibraryA(DllFullPath);
	//HMODULE	DllModule = LoadLibrary(L"E:\\tu\\vs_project\\hook_dll\\x64\\Release\\hook_dll.dll");
	HMODULE	DllModule = LoadLibrary(L"E:\\tu\\vs_project\\hook_dll\\Release\\hook_dll.dll");
	//FARPROC FunctionAddress = GetProcAddress(DllModule, "Sub_1");
	HOOKPROC addr = (HOOKPROC)GetProcAddress(DllModule, "KeyboardProc");
	//FARPROC FunctionAddress = GetProcAddress(DllModule, "KeyboardProc");
	/*int nCode; WPARAM wParam; LPARAM lParam;
	FunctionAddress();*/
	//HookHandle = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)FunctionAddress, DllModule, ThreadId);
	HookHandle = SetWindowsHookEx(WH_KEYBOARD, addr, DllModule, ThreadId);
	if (HookHandle == NULL)
	{
		MessageBoxA(NULL, "456", "456", 0);
		return FALSE;
	}
	return TRUE;
}

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	//MessageBoxA(NULL, "NativeInjectionEntryPoint", "NativeInjectionEntryPoint ", 0);
	int errCode = PrepareRealApiEntry();
	if (errCode != 0)
	{
		OutputDebugString(L"PrepareRealApiEntry() Error\n");
		return;
	}
	//HMODULE hHookQQ = LoadLibrary(TEXT("F:\\tu\\me\\HookQQ-master\\HookQQ-master\\VC\\Release\\HookQQ.dll"));
	//if (hHookQQ == NULL)
	//{
	//	//OutputDebugText(TEXT("Failed to load HookQQ.dll\n"));
	//	return;
	//}
	//开始挂钩  
	DoHook();
	//MessageBoxA(NULL, "1NativeInjectionEntryPoint", "1NativeInjectionEntryPoint ", 0);
	DWORD pid = 0;
	if (inRemoteInfo->UserDataSize == sizeof(DWORD)) {
		pid = *reinterpret_cast<DWORD*>(inRemoteInfo->UserData);
		//MessageBoxA(NULL, "1", "1 ", 0);
	}

	if (GrantPriviledge(SE_DEBUG_NAME) == FALSE)
	{
		printf("GrantPriviledge Error\r\n");
	}
	//	UINT32	ProcessId = 0;
	//#ifdef _WIN64
	//	//	GetProcessIdByProcessImageName(L"Taskmgr.exe", &ProcessId);
	//	//	GetProcessIdByProcessImageName(L"calculator.exe", &ProcessId);
	//	GetProcessIdByProcessImageName(L"QQ.exe", &ProcessId);
	//	//strcat_s(DllFullPath, "\\x64WindowHookDll.dll");
	//#else
	//	GetProcessIdByProcessImageName(L"QQ.exe", &ProcessId);
	//	//strcat_s(DllFullPath, "\\x86WindowHookDll.dll");
	//#endif
	//	vector<UINT32> ThreadIdVector;
	//	GetThreadIdByProcessId(ProcessId, ThreadIdVector);
	//	HHOOK HookHandle = NULL;
	//
	//	for (UINT32 ThreadId : ThreadIdVector)
	//	{
	//		Inject(ThreadId, HookHandle);
	//		//break;
	//	}

	/*BOOL iRet = EnumWindows(noteProc, pid);
	if (!iRet) {
	DWORD iErr = GetLastError();
	printf("EnumWindows error:%ld\n", iRet);
	}*/
	/*HWND notepadhandle = FindWindow(TEXT("Notepad"), NULL);
	DWORD lpdwProcessId = NULL;
	DWORD ThreadId = GetWindowThreadProcessId(notepadhandle, &lpdwProcessId);*/
	//glhHook = SetWindowsHookEx(WH_CALLWNDPROC, myProc, NULL, GetCurrentThreadId());
	//glhHook = SetWindowsHookEx(WH_GETMESSAGE, myProc, glhInstance, ThreadId);
	/*glhHook = SetWindowsHookEx(WH_KEYBOARD, myProc, NULL, ThreadId);
	if (glhHook == NULL) {
	MessageBoxA(NULL, "warn", "warning ", 0);
	}
	MessageBoxA(NULL, "SetWindowsHookEx", "warning ", 0);*/
	return;
}

int PrepareRealApiEntry()
{
	//MessageBoxA(NULL, "PrepareRealApiEntry", "PrepareRealApiEntry ", 0);
	OutputDebugString(L"PrepareRealApiEntry()\n");
	cout << "PrepareRealApiEntry()\n" << endl;

	HMODULE hWs2_32 = LoadLibrary(L"Ws2_32.dll");
	if (hWs2_32 == NULL)
	{
		OutputDebugString(L"LoadLibrary(L\"Ws2_32.dll\") Error\n");
		return -6001;
	}
	realsendto = (ptrMysendto)GetProcAddress(hWs2_32, "sendto");
	if (realsendto == NULL)
	{
		return -6007;
	}

	realrecv = (ptrMysend)GetProcAddress(hWs2_32, "recv");
	if (realrecv == NULL)
	{
		return -6007;
	}

	realsend = (ptrMysend)GetProcAddress(hWs2_32, "send");
	if (realsend == NULL)
	{
		return -6007;
	}

	// 获取真实函数地址  
	HMODULE hKernel32 = LoadLibrary(L"Kernel32.dll");
	if (hKernel32 == NULL)
	{
		OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") Error\n");
		return -6002;
	}
	OutputDebugString(L"LoadLibrary(L\"Kernel32.dll\") OK\n");
	cout << "LoadLibrary(L\"Kernel32.dll\") OK\n" << endl;

	/*realWriteFile = (ptrMyWriteFile)GetProcAddress(hKernel32, "WriteFile");
	if (realWriteFile == NULL)
	{
	OutputDebugString(L"(ptrCreateFileW)GetProcAddress(hKernel32, \"CreateFileW\") Error\n");
	return -6007;
	}*/

	realReadFile = (ptrReadFile)GetProcAddress(hKernel32, "ReadFile");
	if (realReadFile == NULL)
	{
		return -6007;
	}

	realCreateFileW = (ptrCreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	if (realCreateFileW == NULL)
	{
		OutputDebugString(L"(ptrCreateFileW)GetProcAddress(hKernel32, \"CreateFileW\") Error\n");
		return -6007;
	}
	OutputDebugString(L"(ptrCreateFileW)GetProcAddress(hKernel32, \"CreateFileW\") OK\n");
	cout << "(ptrCreateFileW)GetProcAddress(hKernel32, \"CreateFileW\") OK\n" << endl;

	realCreateFileA = (ptrCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
	if (realCreateFileA == NULL)
	{
		OutputDebugString(L"(ptrCreateFileA)GetProcAddress(hKernel32, \"CreateFileA\") Error\n");
		return -6007;
	}
	OutputDebugString(L"(ptrCreateFileA)GetProcAddress(hKernel32, \"CreateFileA\") OK\n");
	cout << "(ptrCreateFileA)GetProcAddress(hKernel32, \"CreateFileA\") OK\n" << endl;

	/*cout << "GetProcAddress CreateProcessW" << endl;
	realCreateProcessW = (ptrCreateProcessW)GetProcAddress(hKernel32, "CreateProcessW");
	if (realCreateProcessW == NULL)
	{
	return -1;
	}
	cout << "GetProcAddress CreateProcessA" << endl;
	realCreateProcessA = (ptrCreateProcessA)GetProcAddress(hKernel32, "CreateProcessA");
	if (realCreateProcessA == NULL)
	{
	return -1;
	}*/

	//DWORD pID = GetProcessIdOfThread(GetCurrentThread());
	//EnumWindows();

	/*FILE *fp = NULL;
	fopen_s(&fp, "E:\\test.txt", "a+");
	fwrite(L"123", sizeof(int), lstrlen(L"123"), fp);
	fclose(fp);*/

	//STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	//si = { sizeof(si) };
	////si.dwFlags = STARTF_USESHOWWINDOW;//指定wShowWindow成员有效
	////si.wShowWindow = TRUE;
	//TCHAR szCommandLine[] = TEXT("NOTEPAD");
	///*ZeroMemory(&si, sizeof(si));
	//si.cb = sizeof(si);
	//ZeroMemory(&pi, sizeof(pi));*/
	//getchar();
	//cout << "hook CreateProcess before" << endl;
	////if (!CreateProcess(NULL, TEXT("C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1705.1301.0_x64__8wekyb3d8bbwe\Calculator.exe"), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	//if (!CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	//{
	//	cout << "CreateProcess" << endl;
	//	getchar();
	//	return -1;
	//}

	return 0;
}

void DoHook()
{
	//CreateFile();
	OutputDebugString(L"DoHook()\n");

	//statue = LhInstallHook(realWriteFile,
	//	MyWriteFile,
	//	/*(PVOID)0x12345678*/NULL,
	//	hHookWriteFile);
	//if (!SUCCEEDED(statue))
	//{
	//	switch (statue)
	//	{
	//	case STATUS_NO_MEMORY:
	//		OutputDebugString(L"STATUS_NO_MEMORY\n");
	//		break;
	//	case STATUS_NOT_SUPPORTED:
	//		OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
	//		break;
	//	case STATUS_INSUFFICIENT_RESOURCES:
	//		OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
	//		break;
	//	default:
	//		WCHAR dbgstr[512] = { 0 };
	//		wsprintf(dbgstr, L"%d\n", statue);
	//		OutputDebugString(dbgstr);
	//	}
	//	OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");
	//	return;
	//}

	statue = LhInstallHook(realrecv,
		Myrecv,
		/*(PVOID)0x12345678*/NULL,
		hHookrecv);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");
		return;
	}

	statue = LhInstallHook(realsend,
		Mysend,
		/*(PVOID)0x12345678*/NULL,
		hHooksend);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");
		return;
	}

	statue = LhInstallHook(realsendto,
		Mysendto,
		/*(PVOID)0x12345678*/NULL,
		hHooksendto);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");
		return;
	}

	statue = LhInstallHook(realReadFile,
		MyReadFile,
		/*(PVOID)0x12345678*/NULL,
		hHookReadFile);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileW\"),MyCreateFileW,(PVOID)0x12345678,hHookCreateFileW); Error\n");
		return;
	}

	statue = LhInstallHook(realCreateFileW,
		MyCreateFileW,
		/*(PVOID)0x12345678*/NULL,
		hHookCreateFileW);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileW\"),MyCreateFileW,(PVOID)0x12345678,hHookCreateFileW); Error\n");
		return;
	}
	OutputDebugString(L"Hook CreateFileW OK\n");

	statue = LhInstallHook(realCreateFileA,
		MyCreateFileA,
		/*(PVOID)0x12345678*/NULL,
		hHookCreateFileA);
	if (!SUCCEEDED(statue))
	{
		switch (statue)
		{
		case STATUS_NO_MEMORY:
			OutputDebugString(L"STATUS_NO_MEMORY\n");
			break;
		case STATUS_NOT_SUPPORTED:
			OutputDebugString(L"STATUS_NOT_SUPPORTED\n");
			break;
		case STATUS_INSUFFICIENT_RESOURCES:
			OutputDebugString(L"STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		default:
			WCHAR dbgstr[512] = { 0 };
			wsprintf(dbgstr, L"%d\n", statue);
			OutputDebugString(dbgstr);
		}
		OutputDebugString(L"LhInstallHook(GetProcAddress(hKernel32, \"CreateFileA\"),MyCreateFileA,(PVOID)0x12345678,hHookCreateFileA); Error\n");
		return;
	}
	OutputDebugString(L"Hook CreateFileA OK\n");

	/*NTSTATUS result1 = LhInstallHook(
	realCreateProcessW,
	myCreateProcessW,
	NULL,
	hHookCreateProcessW);
	if (FAILED(result1))
	{
	wstring s(RtlGetLastErrorString());
	wcout << "Failed to install hook: ";
	wcout << s.c_str();
	cout << "\n\nPress any key to exit.";
	cin.get();
	return;
	}
	cout << "LhInstallHook CreateProcessA" << endl;
	NTSTATUS result2 = LhInstallHook(
	realCreateProcessA,
	myCreateProcessA,
	NULL,
	hHookCreateProcessA);
	if (FAILED(result2))
	{
	wstring s(RtlGetLastErrorString());
	wcout << "Failed to install hook: ";
	wcout << s.c_str();
	cout << "\n\nPress any key to exit.";
	cin.get();
	return ;
	}
	cout << "LhInstallHook CreateProcessW" << endl;*/


	// 一定要调用这个函数，否则注入的钩子无法正常运行。  
	//LhSetExclusiveACL(HookCreateFileA_ACLEntries, 1, hHookCreateFileA);
	LhSetExclusiveACL(HookCreateFileW_ACLEntries, 1, hHookCreateFileW);
	//LhSetExclusiveACL(HookWriteFile_ACLEntries, 1, hHookWriteFile);
	LhSetExclusiveACL(HookReadFile_ACLEntries, 1, hHookReadFile);

	//LhSetExclusiveACL(Hooksendto_ACLEntries, 1, hHooksendto);
	LhSetExclusiveACL(Hooksend_ACLEntries, 1, hHooksend);
	//LhSetExclusiveACL(Hookrecv_ACLEntries, 1, hHookrecv);


	/*LhSetInclusiveACL(HookCreateFileW_ACLEntries, 1, hHookCreateFileA);
	LhSetInclusiveACL(HookCreateFileW_ACLEntries, 1, hHookCreateFileW);*/

	/*LhSetInclusiveACL(HookCreateProcessW_ACLEntries, 1, hHookCreateProcessW);
	LhSetInclusiveACL(HookCreateProcessA_ACLEntries, 1, hHookCreateProcessA);*/

	/*LhSetExclusiveACL(HookCreateProcessA_ACLEntries, 1, hHookCreateProcessA);
	LhSetExclusiveACL(HookCreateProcessW_ACLEntries, 1, hHookCreateProcessW);*/


}

void DoneHook()
{
	OutputDebugString(L"DoneHook()\n");

	// this will also invalidate "hHook", because it is a traced handle...  
	LhUninstallAllHooks();

	// this will do nothing because the hook is already removed...  
	LhUninstallHook(hHookrecv);
	LhUninstallHook(hHooksend);
	LhUninstallHook(hHooksendto);
	//LhUninstallHook(hHookWriteFile);
	LhUninstallHook(hHookCreateFileA);
	LhUninstallHook(hHookCreateFileW);
	LhUninstallHook(hHookReadFile);

	/*LhUninstallHook(hHookCreateProcessW);
	LhUninstallHook(hHookCreateProcessA);*/

	// now we can safely release the traced handle  
	delete hHooksendto;
	hHooksendto = NULL;

	delete hHookrecv;
	hHookrecv = NULL;

	delete hHooksend;
	hHooksend = NULL;

	/*delete hHookWriteFile;
	hHookWriteFile = NULL;*/

	delete hHookCreateFileA;
	hHookCreateFileA = NULL;

	delete hHookCreateFileW;
	hHookCreateFileW = NULL;

	delete hHookReadFile;
	hHookReadFile = NULL;

	delete hHookCreateProcessW;
	hHookCreateProcessW = NULL;

	delete hHookCreateProcessA;
	hHookCreateProcessA = NULL;

	// even if the hook is removed, we need to wait for memory release  
	LhWaitForPendingRemovals();
}
unsigned int WINAPI WorkerThread(void *para)
{
	while (WAIT_OBJECT_0 != WaitForSingleObject(hExitEvent, 0))
	{
		
		struct timeval tm;
		int len, err = -1;
		tm.tv_sec = 8;
		tm.tv_usec = 0;
		fd_set wset;
		fd_set rset;
		//FD_ZERO(&wset);
		FD_ZERO(&rset);
		//FD_SET(sockfd, &wset);
		FD_SET(sockfd, &rset);
		char buffer[1024] = {0};
		int retval = select(sockfd + 1, &rset, NULL, NULL, &tm);
		switch (retval)
		{
			case -1:
			{
				perror("select");
				break;;
			}
			case 0:
			{
				//MessageBoxA(NULL, "1", "1 ", 0);
				printf("connect timeout\n");
				break;;
			}
			case 1:
			{
				/*if (FD_ISSET(sockfd, &wset))
				{
				printlog("build connect successfully!\n");
				}*/
				if (FD_ISSET(sockfd, &rset))
				{
					int bytes_read = 0;
					LONG nLength = 0;
					bytes_read = recv(sockfd, buffer, 1024, 0);
					if (bytes_read < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							return -1;
						}
						else {
							return -1;
						}
					}
					else if (bytes_read == 0) {
						return -1;
					}
					else if (bytes_read > 0) {
						int idx = 0;
						//LONG StartTime;
						memcpy(&StartTime, buffer + idx, sizeof(LONG));
						idx += sizeof(LONG);
						//LONG EndTime;
						memcpy(&EndTime, buffer + idx, sizeof(LONG));
						idx += sizeof(LONG);
						int nActionName;
						memcpy(&nActionName, buffer + idx, sizeof(int));
						idx += sizeof(int);
						//char sActionName[20] = {0};
						memcpy(sActionName, buffer + idx, nActionName);
						idx += nActionName;
						int nTriggleExpr;
						memcpy(&nTriggleExpr, buffer + idx, sizeof(int));
						idx += sizeof(int);
						//char sTriggleExpr[100] = {0};
						memcpy(sTriggleExpr, buffer + idx, nTriggleExpr);
						//MessageBoxA(NULL, sTriggleExpr, "8 ", 0);
						idx += nTriggleExpr;
						int nObjInstallPath;
						memcpy(&nObjInstallPath, buffer + idx, sizeof(int));
						idx += sizeof(int);
						memcpy(sObjInstallPath, buffer + idx, nObjInstallPath);
						idx += nObjInstallPath;
						//MessageBoxA(NULL, sObjInstallPath, "8 ", 0);

						char *temp = strtok(sObjInstallPath, "\\");
						while (temp)
						{
							if (strcmp(temp, "QQ") == 0)
								break;
							if (icount == 1) {
								path1 = temp;
								path1 += "\\";
							}
							if (icount == 2) {
								path2 = path1;
								path2 += temp;
								path2 += "\\";
							}
							if (icount == 3) {
								path3 = path2;
								path3 += temp;
								path3 += "\\";
							}
							if (icount == 4) {
								path4 = path3;
								path4 += temp;
								path4 += "\\";
							}
							if (icount == 5) {
								path5 = path4;
								path5 += temp;
								path5 += "\\";
							}
							if (icount == 6) {
								path6 = path5;
								path6 += temp;
								path6 += "\\";
							}
							if (icount == 7) {
								path7 = path6;
								path7 += temp;
								path7 += "\\";
							}
							if (icount == 8) {
								path8 = path7;
								path8 += temp;
								path8 += "\\";
							}
							if (icount == 9) {
								path9 = path8;
								path9 += temp;
								path9 += "\\";
							}
							temp = strtok(NULL, "\\");
							icount++;
						}
						switch (icount) {
							case 1:{
								break;
							}
						}
					
						
					}
				
				}
				break;
			}
			default:
			{
				/*if (FD_ISSET(sockfd, &wset))
				{
					if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&err, (socklen_t *)&len) < 0)
					{
						
					}
					if (err != 0)
					{
			
					}
				}*/
				break;
			}
		}
	}
	return 0;
}

int ConnectAgentServer()
{
	GetEnvironmentVariable(L"WINDIR", sWindir, 100);
	GetEnvironmentVariable(L"USERPROFILE", sUserprofiledir, 100);
	GetEnvironmentVariable(L"APPDATA", sAppdatadir, 100);
	GetEnvironmentVariable(L"PROGRAMFILES", sProgramfilesdir, 100);
	GetEnvironmentVariable(L"COMMONPROGRAMFILES", sCommonprogramfilesdir, 100); 
	GetEnvironmentVariable(L"ALLUSERSPROFILE", sAllusersprofiledir, 100);
	GetEnvironmentVariable(L"TEMP", sTempdir, 100);

	hTimer = NULL;
	hTimerQueue = NULL;
	hTimerQueue = CreateTimerQueue();
	if (NULL == hTimerQueue)
	{
		return -1;
	}
	hExitEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	WSAData wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		MessageBox(NULL, L"WorkerThread error", L"BHO", MB_OK);
		cout << "WSAStartup error" << endl;
		return 0;
	}

	sockfd = INVALID_SOCKET;
	//SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd == INVALID_SOCKET) {
		//MessageBox(NULL, L"socket error", L"BHO", MB_OK);
		return -1;
	}

	//struct sockaddr_in	service;
	SOCKADDR_IN service;
	ZeroMemory(&service, sizeof(service));
	service.sin_family = AF_INET;
	//service.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	inet_pton(AF_INET, "127.0.0.1", &service.sin_addr);
	service.sin_port = htons(12345);

	int reuse = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	if (connect(sockfd, (struct sockaddr*)&service, sizeof(service)) != 0) {
		closesocket(sockfd);
		sockfd = INVALID_SOCKET;
		//MessageBox(NULL, L"connect error", L"BHO", MB_OK);
	}
	HANDLE ThreadHandle = (HANDLE)_beginthreadex(NULL, 0, WorkerThread, NULL, 0, NULL);
	if (NULL == ThreadHandle) {
		//MessageBox(NULL, L"_beginthreadex error", L"BHO", MB_OK);
		return -1;
	}
	CloseHandle(ThreadHandle);

	int aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + strlen("1") + 1;
	char *data = (char*)malloc(aLen * sizeof(char));
	//char data[sizeof(PKG_HEAD_STRUCT) + sizeof(BODYInfo)] = { 0 };
	PKG_BODY_STRUCT *pReport = reinterpret_cast<PKG_BODY_STRUCT*>(data + sizeof(PKG_CLIENT_HEAD_STRUCT));

	//memcpy(pReport->buffer, html.c_str(), html.length());
	memcpy(pReport->data, "1", strlen("1"));

	PKG_CLIENT_HEAD_STRUCT *pHead = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data);
	pHead->action = PACKET_ACTION_GET;
	pHead->check = PACKET_ENCRYPTION_NONE;
	pHead->command = PACKET_CLIENT_COMMAND_REQUEST_QQ_RULE;
	pHead->pkgInfo.pkg_qq.nLocalIPLength = 0;
	pHead->pkgInfo.pkg_qq.nReceiverIPLength = 0;
	pHead->pkgInfo.pkg_qq.nSenderQQLength = 0;
	pHead->pkgInfo.pkg_qq.nSendFilePathLength = 0;
	pHead->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + strlen("1");
	pHead->pkgTag = 0;
	int nLen = pHead->pkgSize;
	send(sockfd, (char*)pHead, nLen, 0);

	return 0;
}

int errCode = 0;
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	//int errCode = 0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString(L"DllMain::DLL_PROCESS_ATTACH\n");
		cout << "DllMain::DLL_PROCESS_ATTACH\n" << endl;
		glhInstance = hModule;
		hM = hModule;
		ConnectAgentServer();
		//MessageBoxA(NULL, "7", "8 ", 0);
		//errCode = PrepareRealApiEntry();
		//if (errCode != 0)
		//{
		//	OutputDebugString(L"PrepareRealApiEntry() Error\n");
		//	return FALSE;
		//}

		// //开始挂钩  
		//DoHook();
		break;
	case DLL_THREAD_ATTACH:
		OutputDebugString(L"DllMain::DLL_THREAD_ATTACH\n");
		/*errCode = PrepareRealApiEntry();
		if (errCode != 0)
		{
		OutputDebugString(L"PrepareRealApiEntry() Error\n");
		return FALSE;
		}
		break;*/
	case DLL_THREAD_DETACH:
		OutputDebugString(L"DllMain::DLL_THREAD_DETACH\n");
		/*errCode = PrepareRealApiEntry();
		if (errCode != 0)
		{
		OutputDebugString(L"PrepareRealApiEntry() Error\n");
		return FALSE;
		}*/
		//MessageBoxA(NULL, "2", "2 ", 0);
		break;
	case DLL_PROCESS_DETACH:
		SetEvent(hExitEvent);
		OutputDebugString(L"DllMain::DLL_PROCESS_DETACH\n");
		//MessageBoxA(NULL, "3", "3 ", 0);
		//UnhookWindowsHookEx(glhHook);
		//DoneHook();
		break;
	}
	return TRUE;
}

int WINAPI add(int a, int b)
{
	MessageBoxA(NULL, "5", "5 ", 0);
	return a + b;
}

BOOL WINAPI myCreateProcessA(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	)
{
	if (realCreateProcessA == NULL) {
		return -1;
	}

	cout << "\n CreateProcessA All your add belong to us!\n\n";

	cout << "Uninstall hook\n";
	LhUninstallHook(hHookCreateProcessA);

	cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
	LhWaitForPendingRemovals();

	hHookCreateProcessA = NULL;

	/*STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));*/
	return 0;
	//return ::CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

}

BOOL WINAPI myCreateProcessW(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	)
{
	if (realCreateProcessW == NULL) {
		return -1;
	}

	cout << "\n CreateProcessW All your add belong to us!\n\n";

	cout << "Uninstall hook\n";
	LhUninstallHook(hHookCreateProcessW);

	cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
	LhWaitForPendingRemovals();

	hHookCreateProcessW = NULL;

	/*STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));*/
	return 0;
	//return ::CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
static BOOL tutemp = FALSE;
BOOL FilterObjectFile(LPCWSTR lpFileName1)
{
	wchar_t lpFileName[100] = { 0 };
	char pcstr[100] = {0};
	int nLength = wcslen(lpFileName1);
	memcpy(lpFileName, lpFileName1, lstrlen(lpFileName1));
	int nBytes = WideCharToMultiByte(0, 0, lpFileName, nLength, NULL, 0, NULL, NULL);
	WideCharToMultiByte(0, 0, lpFileName, nLength, pcstr, nBytes, NULL, NULL);
	if (StrStr(lpFileName, L"F:\\tu\\install\\qqfile")) {
		return FALSE;
	}
	switch (icount - 1) {
		case 1:{
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			break;
		}
		case 2:{
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			else if (strstr(pcstr, path2.c_str())) {
				return FALSE;
			}
			break;
		}
		case 3:{
			//MessageBoxA(NULL, "3", "1", 0);
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path2.c_str()) == 0) {
				return FALSE;
			}
			else if (strstr(pcstr, path3.c_str())) {
				return FALSE;
			}
			break;
		}
		case 4:{
			//MessageBoxA(NULL, pcstr, "45", 0);
			if (strcmp(pcstr, path1.c_str()) == 0) {
				//MessageBoxA(NULL, path1.c_str(), "1", 0);
				return FALSE;
			}
			else if (strcmp(pcstr, path2.c_str()) == 0) {
				//MessageBoxA(NULL, path2.c_str(), "2", 0);
				return FALSE;
			}
			else if (strcmp(pcstr, path3.c_str()) == 0) {
				//MessageBoxA(NULL, path3.c_str(), "3", 0);
				return FALSE;
			}
			else if (strstr(pcstr, path4.c_str())) {
				//MessageBoxA(NULL, path4.c_str(), "4", 0);
				return FALSE;
			}
			//MessageBoxA(NULL, pcstr, "46", 0);
			break;
		}
		case 5:{
			//MessageBoxA(NULL, "5", "1", 0);
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path2.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path3.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path4.c_str()) == 0) {
				return FALSE;
			}
			else if (strstr(pcstr, path5.c_str())) {
				return FALSE;
			}
			break;
		}
		case 6:{
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path2.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path3.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path4.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path5.c_str()) == 0) {
				return FALSE;
			}
			else if (strstr(pcstr, path6.c_str())) {
				return FALSE;
			}
			break;
		}
		case 7:{
			if (strcmp(pcstr, path1.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path2.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path3.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path4.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path5.c_str()) == 0) {
				return FALSE;
			}
			else if (strcmp(pcstr, path6.c_str()) == 0) {
				return FALSE;
			}
			else if (strstr(pcstr, path7.c_str())) {
				return FALSE;
			}
			break;
		}
		case 8:{
			break;
		}
		case 9:{
			break;
		}
		default:
			break;
	}

	if (StrStr(lpFileName, sWindir)) {
		return FALSE;
	}

	else if (StrStr(lpFileName, L"C:\\Windows")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\\windows")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"desktop.ini")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"\\AppData\\Roaming")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, sUserprofiledir)) {

		if (StrStr(lpFileName, L"Desktop")) {

			if (StrStr(lpFileName, L"desktop.ini")) {
				//MessageBoxA(NULL, "55", "55", 0);
				return FALSE;
			}
			else if (StrStr(lpFileName, L".lnk")) {
				return FALSE;
			}
			else {
				return TRUE;
			}
		}
		else if (StrStr(lpFileName, L"Documents")) {
			 if (StrStr(lpFileName, L"Tencent Files")) 
				return FALSE;

		}
		//return FALSE;
	}
	else if (StrStr(lpFileName, sAppdatadir)) {
		return FALSE;
	}
	else if (StrStr(lpFileName, sProgramfilesdir)) {
		return FALSE;
	}
	else if (StrStr(lpFileName, sCommonprogramfilesdir)) {
		return FALSE;
	}
	else if (StrStr(lpFileName, sAllusersprofiledir)) {
		return FALSE;
	}
	else if (StrStr(lpFileName, sTempdir)) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\~")) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"C") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"C:") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"C:\\") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"C:\\Users") == 0) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\1")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\2")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\3")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\4")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\5")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\6")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\7")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\8")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"C:\9")) {
		return FALSE;
	}
	else if (StrStr(lpFileName, L"\\\.")) {
		return FALSE;
	}
	/*else if (StrStr(lpFileName, L" ")) {
		return FALSE;
	}*/
	else if (StrStr(lpFileName, L"guard_qq.dll")) {
		return FALSE;
	}
	/*else if (StrStr(lpFileName, L'\0')) {
		return FALSE;
	}
	else if (StrChr(lpFileName, L'\0')) {
		return FALSE;
	}*/
	else if (StrStr(lpFileName, L"C:\$Directory")) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"E") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"E ") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"E:") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"E:\\") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"F") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"F ") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"F:") == 0) {
		return FALSE;
	}
	else if (StrCmp(lpFileName, L"F:\\") == 0) {
		return FALSE;
	}

	return TRUE;
}

//TODO
static BOOL bFirst = FALSE;
static int nCount = 0;
HANDLE WINAPI MyCreateFileW(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	)
{
	HANDLE hHandle = NULL;
	wchar_t lpFileName1[100] = { 0 };
	memcpy(lpFileName1, lpFileName, lstrlen(lpFileName));
	/*char pcstr[100] = { 0 };
	int nLength = wcslen(lpFileName);
	int nBytes = WideCharToMultiByte(0, 0, lpFileName, nLength, NULL, 0, NULL, NULL);
	WideCharToMultiByte(0, 0, lpFileName, nLength, pcstr, nBytes, NULL, NULL);*/

	// 执行钩子  
	if (realCreateFileW == NULL)
	{
		OutputDebugString(L"realCreateFileW is NULL\n");
		return INVALID_HANDLE_VALUE;
	}
	else
	{
		if (FilterObjectFile(lpFileName)) {

			if (StrStr(lpFileName, L"C:\\Windows")) {
				goto TURNEND;
			}
			else if (StrStr(lpFileName, L"F:\\tu\\install\\qqfile")) {
				goto TURNEND;
			}
			else if (StrStr(lpFileName, L"Tencent")) {
				goto TURNEND;
			}

			g_hHandle = (realCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,
				lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
			//memcpy(g_sFilePath, lpFileName, lstrlen(lpFileName));
			//MessageBoxW(NULL, lpFileName, L"66", 0);
			return g_hHandle;
		}
	TURNEND:
		hHandle = (realCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode,
			lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		/*OutputDebugString(L"MyCreateFileW : ");
		OutputDebugString(lpFileName);
		OutputDebugString(L"\n");*/
		/*cout << "Uninstall hook\n";
		LhUninstallHook(hHookCreateFileW);

		cout << "\n\nRestore ALL entry points of pending removals issued by LhUninstallHook()\n";
		LhWaitForPendingRemovals();

		hHookCreateFileW = NULL;*/

	}

	return hHandle;
}

HANDLE WINAPI MyCreateFileA(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	)
{
	HANDLE hHandle = NULL;

	// 执行钩子  
	if (realCreateFileA == NULL)
	{
		OutputDebugString(L"realCreateFileA is NULL\n");
		return INVALID_HANDLE_VALUE;
	}
	else
	{
		/*FILE *fp = NULL;
		fopen_s(&fp, "E:\\test.txt", "a+");
		fwrite(lpFileName, sizeof(char), strlen(lpFileName), fp);
		fclose(fp);
		OutputDebugString(L"realCreateFileA is not NULL\n");*/
		// MessageBoxA(NULL, "MyCreateFileA", "MyCreateFileA ", 0);
		/*time_t tm = time(0);
		if (tm >= StartTime && tm <= EndTime) {
			int aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + strlen("1") + 1;
			char *data = (char*)malloc(aLen * sizeof(char));
			//char data[sizeof(PKG_HEAD_STRUCT) + sizeof(BODYInfo)] = { 0 };
			PKG_BODY_STRUCT *pReport = reinterpret_cast<PKG_BODY_STRUCT*>(data + sizeof(PKG_CLIENT_HEAD_STRUCT));

			//memcpy(pReport->buffer, html.c_str(), html.length());
			memcpy(pReport->data, "1", strlen("1"));

			PPKG_CLIENT_HEAD_STRUCT pHead = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data);
			pHead->action = PACKET_ACTION_POST;
			pHead->check = PACKET_ENCRYPTION_NONE;
			pHead->command = PACKET_CLIENT_COMMAND_REQUEST_START_RECORD_DESKTOP;
			pHead->pkgInfo.pkg_qq.nLocalIPLength = 0;
			pHead->pkgInfo.pkg_qq.nReceiverIPLength = 0;
			pHead->pkgInfo.pkg_qq.nSenderQQLength = 0;
			pHead->pkgInfo.pkg_qq.nSendFilePathLength = 0;
			pHead->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + strlen("1");
			pHead->pkgTag = 0;
			send(sockfd, (char*)pHead, pHead->pkgSize, 0);

			int len = pHead->pkgSize;
			int bytes_write = 0;
			while (1)
			{
				bytes_write = send(sockfd, (char*)pHead, len, 0);
				if (bytes_write == -1) {
					//return FALSE;
				}
				else if (bytes_write == 0) {
					//return FALSE;
				}
				len -= bytes_write;
				pHead = pHead + bytes_write;
				if (len <= 0) {
					//return TRUE;
				}
			}

			Sleep(10);
			free(data);

			aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + strlen(lpFileName) + 1;
			char *data1 = (char*)malloc(aLen * sizeof(char));
			//char data[sizeof(PKG_HEAD_STRUCT) + sizeof(BODYInfo)] = { 0 };
			PKG_BODY_STRUCT *pReport1 = reinterpret_cast<PKG_BODY_STRUCT*>(data1 + sizeof(PKG_CLIENT_HEAD_STRUCT));

			//memcpy(pReport->buffer, html.c_str(), html.length());
			memcpy(pReport1->data, lpFileName, strlen(lpFileName));

			PPKG_CLIENT_HEAD_STRUCT pHead1 = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data1);
			pHead1->action = PACKET_ACTION_POST;
			pHead1->check = PACKET_ENCRYPTION_NONE;
			pHead1->command = PACKET_CLIENT_COMMAND_POST_QQ_INFO;
			pHead1->pkgInfo.pkg_qq.nLocalIPLength = 0;
			pHead1->pkgInfo.pkg_qq.nReceiverIPLength = 0;
			pHead1->pkgInfo.pkg_qq.nSenderQQLength = 0;
			pHead1->pkgInfo.pkg_qq.nSendFilePathLength = strlen(lpFileName);
			pHead1->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + strlen(lpFileName);
			pHead1->pkgTag = 0;
			send(sockfd, (char*)pHead1, pHead1->pkgSize, 0);
		}
		*/
		hHandle = (realCreateFileA)(lpFileName, dwDesiredAccess, dwShareMode,
			lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

		/*OutputDebugString(L"MyCreateFileW : ");
		OutputDebugStringA(lpFileName);
		OutputDebugString(L"\n");*/
	}

	return hHandle;
}

BOOL GetPosition(LPSTR lpIPAddress, LPWSTR lpPosition, size_t length)
{
	HINTERNET hInt = NULL;
	HINTERNET hUrl = NULL;
	TCHAR tzUrl[100] = { 0 };
	CHAR szFile[0x6000] = { 0 };
	DWORD dwFileLen = 0;

	hInt = InternetOpen(TEXT("HookQQ"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInt == NULL)
	{
		//DbgPrint((TEXT("InternetOpen error code: %x\n"), GetLastError()));
		return FALSE;
	}

	wsprintf(tzUrl, TEXT("http://ip.chinaz.com/?IP=%hs"), lpIPAddress);
	hUrl = InternetOpenUrl(hInt, tzUrl, NULL, 0, INTERNET_FLAG_NEED_FILE, 0);
	if (hUrl == NULL)
	{
		//DbgPrint((TEXT("InternetOpenUrl error code: %x\n"), GetLastError()));
		InternetCloseHandle(hInt);
		return FALSE;
	}

	while (InternetReadFile(hUrl, szFile, sizeof(szFile), &dwFileLen))
	{
		LPSTR lpStart = NULL;
		LPSTR lpEnd = NULL;
		WCHAR wzPosition[100] = { 0 };

		if (dwFileLen < 0x5000)
			continue;

		lpStart = strstr(szFile, "==>>");
		lpStart = strstr(lpStart + 1, "==>") + 5;
		lpEnd = strstr(lpStart, "</strong>");
		*lpEnd = 0;
		MultiByteToWideChar(CP_UTF8, 0, lpStart, lpEnd - lpStart + 1, lpPosition, length);
		break;
	}

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInt);

	return TRUE;
}

//static INT nSame = 0;
char remoteIP[20] = {0};
int WSAAPI Mysendto(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags,
	_In_reads_bytes_(tolen) const struct sockaddr FAR * to,
	_In_ int tolen
	)
{
	//MessageBoxA(NULL, "Mysendto", "Mysendto", 0);
	//CHAR *QQIP = NULL;
	//DWORD QQID = 0;
	//int index = 0;
	//WCHAR wzPosition[100] = { 0 };
	//TCHAR tzTemp[0x800] = { 0 };

	////inet_ntop(NULL,);
	//QQIP = inet_ntoa(((sockaddr_in *)to)->sin_addr);
	//wsprintf(tzTemp, TEXT("Len: %d, IP: %hs\n"), len, QQIP);
	//for (index = 0; index < len; ++index)
	//	wsprintf(tzTemp, TEXT("%s%02X"), tzTemp, buf[index]);
	////OutputString((tzTemp));

	//if (len == 27 && *buf == 3)
	//{
	//	QQID = (BYTE)buf[26] | (((BYTE)buf[25] | (((BYTE)buf[24] | ((BYTE)buf[23] << 8)) << 8)) << 8);
	//	GetPosition(QQIP, wzPosition, sizeof(wzPosition));
	//	//OutputString(TEXT("Position: %ls, QQID: %d\n"), wzPosition, QQID);
	//	char temp[15] = {0};
	//	sprintf(temp, "%d", QQID);
	//	FILE *fp = NULL;
	//	fopen_s(&fp, "E:\\tu\\test.txt", "a+");
	//	fwrite(wzPosition, sizeof(int), lstrlen(wzPosition), fp);
	//	fwrite(temp, sizeof(char), strlen(temp), fp);
	//	fclose(fp);
	//	

	//}
	/*FILE *fp = NULL;
	fopen_s(&fp, "E:\\tu\\sendto.txt", "a+");
	fwrite(buf, sizeof(char), strlen(buf), fp);
	fwrite(to->sa_data, sizeof(char), strlen(to->sa_data), fp);
	fclose(fp);*/
	/*struct sockaddr_in sin;
	ZeroMemory(&sin, sizeof(sin));
	memcpy(&sin, to, sizeof(sin));
	if (nSame > 8) {
		memcpy(g_sReceiverIP, remoteIP, strlen(remoteIP));
		nSame = 0;
	}
	if (strcmp(remoteIP, inet_ntoa(sin.sin_addr)) == 0) {
		nSame++;
	}
	memset(remoteIP, '\0', 20);
	memcpy(remoteIP, inet_ntoa(sin.sin_addr), strlen(inet_ntoa(sin.sin_addr)));*/

	//OutputString(TEXT("\n"));
	return (realsendto)(s, buf, len, flags, to, tolen);
}

BOOL WINAPI MyWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	)
{
	/*FILE *fp = NULL;
	fopen_s(&fp, "E:\\tu\\test.txt", "a+");
	fwrite(L"567", sizeof(int), lstrlen(L"567"), fp);
	fclose(fp);*/
	return (realWriteFile)(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

static BOOL bGetInfo = FALSE;
int WSAAPI Mysend(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags
	)
{
	/*DWORD QQID = 0;
	QQID = (BYTE)buf[26] | (((BYTE)buf[25] | (((BYTE)buf[24] | ((BYTE)buf[23] << 8)) << 8)) << 8);*/
	//char temp[20] = {0};
	////sprintf(temp, "%d", QQID);

	//char host[255] = {0};
	//gethostname(host, sizeof(host));
	//struct hostent *p = gethostbyname(host);
	//struct sockaddr_in addr;
	//struct sockaddr_in peeraddr;
	//socklen_t addr_len = sizeof(addr); 
	//socklen_t peeraddr_len = sizeof(peeraddr);
	//getsockname(s, (struct sockaddr *)&addr, &addr_len);
	//getpeername(s, (struct sockaddr *)&peeraddr, &peeraddr_len);
	//FILE *fp = NULL;
	//fopen_s(&fp, "E:\\tu\\send.txt", "a+");
	////fwrite(temp, sizeof(int), strlen(temp), fp);
	//fwrite(buf, sizeof(char), strlen(buf), fp);
	//fwrite(host, sizeof(char), strlen(host), fp);
	//fwrite(inet_ntoa(addr.sin_addr), sizeof(char), strlen(inet_ntoa(addr.sin_addr)), fp);
	//sprintf(temp, "%d", ntohs(addr.sin_port));
	//fwrite(temp, sizeof(char), strlen(temp), fp);
	//fwrite(inet_ntoa(peeraddr.sin_addr), sizeof(char), strlen(inet_ntoa(peeraddr.sin_addr)), fp);
	//fclose(fp);
	if (!bGetInfo) {
		gethostname(g_sHost, sizeof(g_sHost));
		struct hostent *p = gethostbyname(g_sHost);
		struct sockaddr_in addr;
		struct sockaddr_in peeraddr;
		socklen_t addr_len = sizeof(addr); 
		// socklen_t peeraddr_len = sizeof(peeraddr);
		getsockname(s, (struct sockaddr *)&addr, &addr_len);
		// getpeername(s, (struct sockaddr *)&peeraddr, &peeraddr_len);
		memcpy(g_sSenderIP, inet_ntoa(addr.sin_addr), strlen(inet_ntoa(addr.sin_addr)));
		/*const char *qq = NULL;
		if ((qq = strstr(buf, "uin_cookie="))) {
			memcpy(g_sSenderNum, qq, strlen(qq));
			bGetInfo = TRUE;
		} */
		bGetInfo = TRUE;
	}
	return (realsend)(s, buf, len, flags);
}

int WSAAPI Myrecv(
	_In_  SOCKET s,
	_Out_writes_bytes_(len) const char FAR *buf,
	_In_  int    len,
	_In_  int    flags
	)
{
	//FILE *fp = NULL;
	//fopen_s(&fp, "E:\\tu\\recv.txt", "a+");
	////fwrite(temp, sizeof(int), strlen(temp), fp);
	//fwrite(buf, sizeof(char), strlen(buf), fp);
	//fclose(fp);
	return (realrecv)(s, buf, len, flags);
}

//BOOL WINAPI MyReadFile(
//	_In_ HANDLE hFile,
//	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
//	_In_ DWORD nNumberOfBytesToRead,
//	_Out_opt_ LPDWORD lpNumberOfBytesRead,
//	_Inout_opt_ LPOVERLAPPED lpOverlapped
//	)
//{
//	FILE *fp = NULL;
//	fopen_s(&fp, "E:\\tu\\readfile.txt", "a+");
//	fwrite(lpBuffer, sizeof(char), lstrlen(_T(lpBuffer)), fp);
//	fclose(fp);
//	return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
//}

VOID CALLBACK TimerRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	g_nReady = 0;
	//::InterlockedDecrement(&g_nReady);
	//int aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + strlen(g_sFilePath) + 1;
	//char *data1 = (char*)malloc(aLen * sizeof(char));
	////char data[sizeof(PKG_HEAD_STRUCT) + sizeof(BODYInfo)] = { 0 };
	//PKG_BODY_STRUCT *pReport1 = reinterpret_cast<PKG_BODY_STRUCT*>(data1 + sizeof(PKG_CLIENT_HEAD_STRUCT));

	///*char g_sHost[50] = { 0 };
	//char g_sSenderIP[20] = { 0 };
	//char g_sReceiverIP[20] = { 0 };
	//char g_sSenderNum[20] = { 0 };
	//char g_sTriggleTime[20] = { 0 };
	//*/

	//int index = 0;
	//if (strlen(g_sHost) > 0) {
	//	memcpy(pReport1->data + index, g_sHost, strlen(g_sHost));
	//	index += strlen(g_sHost);
	//	//MessageBoxA(NULL, g_sHost, "1", 0);
	//}
	//if (strlen(g_sSenderIP) > 0) {
	//	memcpy(pReport1->data + index, g_sSenderIP, strlen(g_sSenderIP));
	//	index += strlen(g_sSenderIP);
	//	//MessageBoxA(NULL, g_sSenderIP, "2", 0);
	//}
	//if (strlen(g_sReceiverIP) > 0) {
	//	memcpy(pReport1->data + index, g_sReceiverIP, strlen(g_sReceiverIP));
	//	index += strlen(g_sReceiverIP);
	//}
	//if (strlen(g_sSenderNum) > 0) {
	//	memcpy(pReport1->data + index, g_sSenderNum, strlen(g_sSenderNum));
	//	index += strlen(g_sSenderNum);
	//	//MessageBoxA(NULL, g_sSenderNum, "3", 0);
	//}
	////TCHAR ps2[MAX_PATH + 1];
	////ZeroMemory(ps2, MAX_PATH + 1);
	////memcpy(ps2, (TCHAR*)lpParam, lstrlen((TCHAR*)lpParam));
	////if (lstrlen(ps2) > 0) {
	////	/*memcpy(pReport1->data + index, pszFilename, lstrlen(pszFilename));
	////	index += lstrlen(pszFilename);*/
	////	memcpy(pReport1->data + index, ps2, lstrlen(ps2));
	////	index += lstrlen(ps2);
	////	//MessageBoxW(NULL, (TCHAR*)lpParam, L"4", 0);
	////}
	//memcpy(pReport1->data + index, g_sFilePath, strlen(g_sFilePath));
	//index += strlen(g_sFilePath);

	//memcpy(pReport1->data + index, &g_tTriggleTime, sizeof(int));
	//index += sizeof(int);

	//PPKG_CLIENT_HEAD_STRUCT pHead1 = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data1);
	//pHead1->action = PACKET_ACTION_POST;
	//pHead1->check = PACKET_ENCRYPTION_NONE;
	//pHead1->command = PACKET_CLIENT_COMMAND_POST_QQ_INFO;
	//pHead1->pkgInfo.pkg_qq.nLocalIPLength = strlen(g_sSenderIP);
	//pHead1->pkgInfo.pkg_qq.nReceiverIPLength = strlen(g_sReceiverIP);
	//pHead1->pkgInfo.pkg_qq.nSenderQQLength = strlen(g_sSenderNum);
	//pHead1->pkgInfo.pkg_qq.nSendFilePathLength = strlen(g_sFilePath);
	//pHead1->pkgInfo.pkg_qq.nTriggleTime = sizeof(int);
	//pHead1->pkgInfo.pkg_qq.nHostName = strlen(g_sHost);
	//pHead1->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + index;
	//pHead1->pkgTag = 0;
	//send(sockfd, (char*)pHead1, pHead1->pkgSize, 0);
	//free(data1);
}


BOOL GetFileNameFromHandle(HANDLE hFile)
{
	BOOL bSuccess = FALSE;
	//TCHAR pszFilename[MAX_PATH + 1];
	HANDLE hFileMap;

	// Get the file size.
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

	if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
	{
		_tprintf(TEXT("Cannot map a file with a length of zero.\n"));
		return FALSE;
	}

	// Create a file mapping object.
	hFileMap = CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,
		1,
		NULL);

	if (hFileMap)
	{
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem)
		{
			if (GetMappedFileName(GetCurrentProcess(),
				pMem,
				pszFilename,
				MAX_PATH))
			{

				// Translate path with device name to drive letters.
				TCHAR szTemp[BUFSIZE];
				szTemp[0] = '\0';

				if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
				{
					TCHAR szName[MAX_PATH];
					TCHAR szDrive[3] = TEXT(" :");
					BOOL bFound = FALSE;
					TCHAR* p = szTemp;

					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if (QueryDosDevice(szDrive, szName, MAX_PATH))
						{
							size_t uNameLen = _tcslen(szName);

							if (uNameLen < MAX_PATH)
							{
								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
									&& *(pszFilename + uNameLen) == _T('\\');

								if (bFound)
								{
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									TCHAR szTempFile[MAX_PATH];
									StringCchPrintf(szTempFile,
										MAX_PATH,
										TEXT("%s%s"),
										szDrive,
										pszFilename + uNameLen);
									StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
								}
							}
						}

						// Go to the next NULL character.
						while (*p++);
					} while (!bFound && *p); // end of string
				}
			}
			bSuccess = TRUE;
			UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}
	//_tprintf(TEXT("File name is %s\n"), pszFilename);
	return(bSuccess);
}

BOOL WINAPI MyReadFile(
	_In_        HANDLE       hFile,
	_Out_       LPVOID       lpBuffer,
	_In_        DWORD        nNumberOfBytesToRead,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	)
{
	if (hFile == g_hHandle) {

		::InterlockedIncrement(&g_nReady);
		if (::InterlockedDecrement(&g_nReady) == 0) {
			/*if ((strlen(g_sFilePath) == 1) || (strlen(g_sFilePath) == 0)) {

				return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}*/
			/*char param[100] = {0};
			memcpy(param, g_sFilePath, strlen(g_sFilePath));*/
			ZeroMemory(pszFilename, MAX_PATH + 1);
			TCHAR pszFilename2[MAX_PATH + 1];
			ZeroMemory(pszFilename2, MAX_PATH + 1);
			TCHAR pszFilename3[MAX_PATH + 1];
			ZeroMemory(pszFilename3, MAX_PATH + 1);
			GetFileNameFromHandle(hFile);
			if (lstrlen(pszFilename) == 0) {
				return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}
			memcpy(pszFilename2, pszFilename, lstrlen(pszFilename));
			//memcpy(g_sFilePath, pszFilename, lstrlen(pszFilename));
			char pcstr[100] = { 0 };
			int nLength = wcslen(pszFilename2);
			int nBytes = WideCharToMultiByte(0, 0, pszFilename2, nLength, NULL, 0, NULL, NULL);
			WideCharToMultiByte(0, 0, pszFilename2, nLength, pcstr, nBytes, NULL, NULL);
			if (StrStr(pszFilename2, L"C:\\Windows")) {
				return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}
			else if (StrStr(pszFilename2, L"F:\\tu\\install\\qqfile")) {
				return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}
			else if (StrStr(pszFilename2, L"Tencent")) {
				return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}
			
			if (hTimer != NULL) {
				DeleteTimerQueueTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
			}
			if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)TimerRoutine, NULL, 5000, 0, 0)) {
				return FALSE;
			}

			time_t tm = time(0);
			g_tTriggleTime = time(0);
			//if (tm >= StartTime && tm <= EndTime) {

			//通知代理录屏事件
 			int aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + strlen("1") + 1;
			char *data = (char*)malloc(aLen * sizeof(char));
 			PKG_BODY_STRUCT *pReport = reinterpret_cast<PKG_BODY_STRUCT*>(data + sizeof(PKG_CLIENT_HEAD_STRUCT));

			memcpy(pReport->data, "1", strlen("1"));
			PPKG_CLIENT_HEAD_STRUCT pHead = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data);
			pHead->action = PACKET_ACTION_POST;
			pHead->check = PACKET_ENCRYPTION_NONE;
			pHead->command = PACKET_CLIENT_COMMAND_REQUEST_START_RECORD_DESKTOP;
			pHead->pkgInfo.pkg_qq.nLocalIPLength = 0;
			pHead->pkgInfo.pkg_qq.nReceiverIPLength = 0;
			pHead->pkgInfo.pkg_qq.nSenderQQLength = 0;
			pHead->pkgInfo.pkg_qq.nSendFilePathLength = 0;
			pHead->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + strlen("1");
			pHead->pkgTag = 0;
			send(sockfd, (char*)pHead, pHead->pkgSize, 0);
			free(data);
			 

			//获取文件名等信息并返回给代理
			int nLengthAll = strlen(g_sHost) + strlen(g_sSenderIP) + strlen(g_sReceiverIP) + strlen(g_sSenderNum) + strlen(pcstr) + sizeof(int);
			aLen = sizeof(PKG_CLIENT_HEAD_STRUCT) + sizeof(PKG_BODY_STRUCT) + nLengthAll + 1;
			char *data1 = (char*)malloc(aLen * sizeof(char));			 
			PKG_BODY_STRUCT *pReport1 = reinterpret_cast<PKG_BODY_STRUCT*>(data1 + sizeof(PKG_CLIENT_HEAD_STRUCT));

			
			int index = 0;
			 
			if (strlen(g_sHost) > 0) {
				memcpy(pReport1->data + index, g_sHost, strlen(g_sHost));
				index += strlen(g_sHost);
				//MessageBoxA(NULL, g_sHost, "1", 0);
			}

			if (strlen(g_sSenderIP) > 0) {
				memcpy(pReport1->data + index, g_sSenderIP, strlen(g_sSenderIP));
				index += strlen(g_sSenderIP);
				//MessageBoxA(NULL, g_sSenderIP, "2", 0);
			}
			if (strlen(g_sReceiverIP) > 0) {
				memcpy(pReport1->data + index, g_sReceiverIP, strlen(g_sReceiverIP));
				index += strlen(g_sReceiverIP);
			}
			if (strlen(g_sSenderNum) > 0) {
				memcpy(pReport1->data + index, g_sSenderNum, strlen(g_sSenderNum));
				index += strlen(g_sSenderNum);
				//MessageBoxA(NULL, g_sSenderNum, "3", 0);
			}
			if (strlen(pcstr) > 0) {
				memcpy(pReport1->data + index, pcstr, strlen(pcstr));
				index += strlen(pcstr);
				//MessageBoxW(NULL, pszFilename, L"4", 0);
			}

			memcpy(pReport1->data + index, &g_tTriggleTime, sizeof(int));
			index += sizeof(int);

			PPKG_CLIENT_HEAD_STRUCT pHead1 = reinterpret_cast<PKG_CLIENT_HEAD_STRUCT*>(data1);
			pHead1->action = PACKET_ACTION_POST;
			pHead1->check = PACKET_ENCRYPTION_NONE;
			pHead1->command = PACKET_CLIENT_COMMAND_POST_QQ_INFO;
			pHead1->pkgInfo.pkg_qq.nLocalIPLength = strlen(g_sSenderIP);
			pHead1->pkgInfo.pkg_qq.nReceiverIPLength = strlen(g_sReceiverIP);
			pHead1->pkgInfo.pkg_qq.nSenderQQLength = strlen(g_sSenderNum);
			pHead1->pkgInfo.pkg_qq.nSendFilePathLength = strlen(pcstr);
			pHead1->pkgInfo.pkg_qq.nTriggleTime = sizeof(int);
			pHead1->pkgInfo.pkg_qq.nHostName = strlen(g_sHost);
			pHead1->pkgSize = sizeof(PKG_CLIENT_HEAD_STRUCT) + index;
			pHead1->pkgTag = 0;
			send(sockfd, (char*)pHead1, pHead1->pkgSize, 0);
			free(data1);
		}
		::InterlockedIncrement(&g_nReady);
	}

	return (realReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
