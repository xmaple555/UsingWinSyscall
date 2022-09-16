#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"
#include "undocumented.h"

#define out(a,b) if(b) printf(a,b)

int main() 
{
	if (!NTDLL::Initialize()) {
		printf("Failed to Initialize NTDLL.\n");
		return 0;
	}
	if (!Undocumented::UndocumentedInit()) {
		printf("Failed to Initialize Undocumented.\n");
		return 0;
	}

	PVOID PBuffer = NULL;
	HANDLE Heap = GetProcessHeap();
	ULONG cbBuffer = 131072;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	while (1) {
		PBuffer = HeapAlloc(Heap, HEAP_ZERO_MEMORY, cbBuffer);
		if (PBuffer == NULL) {
			return 0;
		}
		Status = Undocumented::NtQuerySystemInformation(SystemProcessInformation, PBuffer, cbBuffer, &cbBuffer);

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(Heap, NULL, PBuffer);
			cbBuffer *= 2;
		}
		else if (!NT_SUCCESS(Status)) {
			HeapFree(Heap, NULL, PBuffer);
			return 0;
		}
		else {
			PSYSTEM_PROCESS_INFORMATION InfomationProcess = NULL;
			InfomationProcess = (PSYSTEM_PROCESS_INFORMATION)PBuffer;
			while (InfomationProcess) {
				out("Process ID: %d\n", InfomationProcess->UniqueProcessId);
				out("Inherited From ID: %d\n", InfomationProcess->InheritedFromUniqueProcessId);
				out("Pagefile Usage: %d\n", InfomationProcess->PagefileUsage);
				out("Working SetSize: %d\n", InfomationProcess->WorkingSetSize);
				out("PageFault Count: %d\n", InfomationProcess->PageFaultCount);
				out("QuadPart (User): %d\n", ((double)InfomationProcess->UserTime.QuadPart) / 1e7);
				out("QuadPart (Kernal): %d\n", ((double)InfomationProcess->KernelTime.QuadPart) / 1e7);

				switch (InfomationProcess->BasePriority) {
				case 4:
					out("Base Priority: %s\n", "Idle");
					break;
				case 8:
					out("Base Priority: %s\n", "Normal");
					break;
				case 13:
					out("Base Priority: %s\n", "High");
					break;
				case 24:
					out("Base Priority: %s\n", "Realtime");
					break;
				}
				char ProcessName[256];
				memset(ProcessName, 0, sizeof(ProcessName));
				WideCharToMultiByte(CP_ACP, 0, InfomationProcess->ImageName.Buffer, InfomationProcess->ImageName.Length, ProcessName, sizeof(ProcessName), NULL, NULL);//w_Char To char
				out("%s\n\n", ProcessName);
				if (!InfomationProcess->NextEntryOffset) break;
				InfomationProcess = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)InfomationProcess) + InfomationProcess->NextEntryOffset);
			}
			if (PBuffer) {
				HeapFree(GetProcessHeap(), NULL, PBuffer);
				break;
			}
			
		}
	}

	NTDLL::Deinitialize();
	Undocumented::DeUndocumentedInit();
	return 0;
}