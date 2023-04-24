#include <windows.h>
#include <iostream>
#include "detours.h"
#include <winternl.h>
#include <ntstatus.h>
#include <string>
#include <lsalookup.h>
#include "pch.h"

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;          // длина строки в байтах
    USHORT MaximumLength;   // размер буфера в байтах
    PWSTR  Buffer;          // указатель на буфер
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;

typedef struct _LSA_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PLSA_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} LSA_OBJECT_ATTRIBUTES, * PLSA_OBJECT_ATTRIBUTES;

typedef LONG NTSTATUS, * PNTSTATUS;
typedef PVOID LSA_HANDLE, * PLSA_HANDLE;

NTSTATUS LsaOpenPolicy(
    PLSA_UNICODE_STRING SystemName,          // имя компьютера
    PLSA_OBJECT_ATTRIBUTES ObjectAttributes, // атрибуты
    ACCESS_MASK DesiredAccess,               // права доступа
    PLSA_HANDLE PolicyHandle                // хэндл объекта политики
);

NTSTATUS(WINAPI* TrueLsaOpenPolicy)(PLSA_UNICODE_STRING SystemName, PLSA_OBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle) = LsaOpenPolicy;

__declspec(dllexport) VOID WINAPI MyLsaOpenPolicy(PLSA_UNICODE_STRING SystemName, PLSA_OBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle)
{

    HANDLE hFile = CreateFile(L"c:\\logfile.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CloseHandle(hFile);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueLsaOpenPolicy, MyLsaOpenPolicy);
        DetourTransactionCommit();
    }

    return TRUE;
}
