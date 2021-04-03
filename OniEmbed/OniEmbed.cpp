#include <Windows.h>
#include <stdio.h>
#include <compressapi.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <string.h>

#pragma comment(lib, "cabinet.lib") //needed for compressapi.h
#define ALIGN(k, y)    (((k)+((y)-1))&(~((y)-1)))

typedef struct {
    wchar_t pHostPath[MAX_PATH];
    LPVOID lpHostMap;
    LPVOID lpShellcodeBuff;
    PIMAGE_DOS_HEADER pHostDosHeader;
    PIMAGE_NT_HEADERS pHostNtHeaders;
    PIMAGE_OPTIONAL_HEADER pHostOptionalHeader;
    PIMAGE_FILE_HEADER pHostFileHeader;
    SIZE_T szHostSize;
    SIZE_T szShellcodeSize;
    SIZE_T szHostSizeOfOptionalHeader;
    DWORD dwHostNumberOfSections;
    DWORD dwHostSectionAlignment;
    DWORD dwHostFileAlignment;
    PIMAGE_SECTION_HEADER pHostFirstSectionHeader;
    PIMAGE_SECTION_HEADER pNewSectionHeader;
    LPVOID lpHostFirstByteOfSectionData;
} INF_PARAM, * PINF_PARAM;

BOOL OniMapFileRW(__in PINF_PARAM pInfParam, __in LPVOID lpTargetBuff, __in SIZE_T szTargetSize) {
    HANDLE hFile = NULL;
    HANDLE hMap = NULL;
    BOOL ret = FALSE;

    pInfParam->szShellcodeSize = szTargetSize;
    pInfParam->lpShellcodeBuff = lpTargetBuff;

    hFile = CreateFile(pInfParam->pHostPath, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    do {
        if (hFile == INVALID_HANDLE_VALUE) {
            puts("[-] Failed to open PE file");
            break;
        }

        pInfParam->szHostSize = GetFileSize(hFile, NULL);
        hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE,
            0, pInfParam->szHostSize + pInfParam->szShellcodeSize, NULL);
        if (!hMap || hMap == INVALID_HANDLE_VALUE) {
            puts("[-] Failed to create file mapping");
            break;
        }

        pInfParam->lpHostMap = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE,
            0, 0, 0);
        if (!pInfParam->lpHostMap) {
            puts("[-] Failed to obtain a map view of PE file");
            break;
        }

        puts("[*] Map View of File created");

        pInfParam->pHostDosHeader = (PIMAGE_DOS_HEADER)pInfParam->lpHostMap;
        if (pInfParam->pHostDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            puts("[-] DOS signature invalid");
            break;
        }

        pInfParam->pHostNtHeaders = (PIMAGE_NT_HEADERS)(
            (PBYTE)pInfParam->lpHostMap + pInfParam->pHostDosHeader->e_lfanew);
        if (pInfParam->pHostNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            puts("[-] NT Signature invalid");
            break;
        }

        pInfParam->dwHostNumberOfSections = pInfParam->pHostNtHeaders->FileHeader.NumberOfSections;
        pInfParam->dwHostSectionAlignment = pInfParam->pHostNtHeaders->OptionalHeader.SectionAlignment;
        pInfParam->dwHostFileAlignment = pInfParam->pHostNtHeaders->OptionalHeader.FileAlignment;
        pInfParam->pHostFileHeader = &pInfParam->pHostNtHeaders->FileHeader;
        pInfParam->szHostSizeOfOptionalHeader = pInfParam->pHostFileHeader->SizeOfOptionalHeader;
        pInfParam->pHostFirstSectionHeader = IMAGE_FIRST_SECTION(pInfParam->pHostNtHeaders);
        pInfParam->pNewSectionHeader = &pInfParam->pHostFirstSectionHeader[pInfParam->dwHostNumberOfSections];
        pInfParam->lpHostFirstByteOfSectionData = (LPVOID)(
            (PBYTE)(DWORD)pInfParam->pHostFirstSectionHeader->PointerToRawData + (DWORD)pInfParam->lpHostMap);
        return TRUE;
        
    } while(0);

    return FALSE;
}

VOID OniAppendSectionHeader(__in PINF_PARAM pInfParam, __in LPCSTR cSectionName) {
    PIMAGE_SECTION_HEADER pLastSectionHeader;
    SIZE_T szAlignedShellcodeSize;

    pLastSectionHeader = &pInfParam->pHostFirstSectionHeader[pInfParam->dwHostNumberOfSections - 1];
    ZeroMemory(pInfParam->pNewSectionHeader, sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(pInfParam->pNewSectionHeader->Name, cSectionName, strlen(cSectionName));

    pInfParam->pNewSectionHeader->Misc.VirtualSize = ALIGN(pInfParam->szShellcodeSize, pInfParam->dwHostSectionAlignment);
    pInfParam->pNewSectionHeader->VirtualAddress = ALIGN(
        pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize, pInfParam->dwHostSectionAlignment);
    pInfParam->pNewSectionHeader->SizeOfRawData = pInfParam->szShellcodeSize;
    pInfParam->pNewSectionHeader->PointerToRawData = (DWORD)(
        pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData);
    pInfParam->pNewSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    pInfParam->dwHostNumberOfSections += 1;
    pInfParam->pHostNtHeaders->FileHeader.NumberOfSections = pInfParam->dwHostNumberOfSections;
    pInfParam->pHostNtHeaders->OptionalHeader.SizeOfImage = ALIGN(
        pInfParam->pHostNtHeaders->OptionalHeader.SizeOfImage + pInfParam->szShellcodeSize,
        pInfParam->dwHostSectionAlignment);

    puts("[+] New Section Header was added successfully");
    return;
}

VOID OniInit(PINF_PARAM pInfParam, wchar_t* wcFilePath) {
    ZeroMemory(pInfParam, sizeof(INF_PARAM));
    CopyMemory(pInfParam->pHostPath, wcFilePath, wcslen(wcFilePath) * sizeof(wchar_t));
}

BOOL OniEmbedBufferInNewFileSection(__in LPVOID lpTargetCodeBuff, __in SIZE_T szTargetCodeSize,
    __in PCHAR pcSectionName, __in wchar_t * pcHostFilePath) {
    INF_PARAM infParam;
    SIZE_T szInjectionSpace;

    puts("[+] Mapping input file");
    OniInit(&infParam, pcHostFilePath);
    OniMapFileRW(&infParam, lpTargetCodeBuff, ALIGN(szTargetCodeSize, USN_PAGE_SIZE));

    szInjectionSpace = ((UINT_PTR)infParam.lpHostFirstByteOfSectionData - ((UINT_PTR)infParam.pNewSectionHeader));
    if (szInjectionSpace < sizeof(IMAGE_SECTION_HEADER)) {
        puts("[-] There is no room for the new section header");
        return FALSE;
    }

    puts("[+] Injecting New Section Header");
    OniAppendSectionHeader(&infParam, pcSectionName);

    puts("[+] Inserting code into new created section");
    CopyMemory((LPVOID)((PBYTE)infParam.lpHostMap + infParam.pNewSectionHeader->PointerToRawData),
        lpTargetCodeBuff, infParam.pNewSectionHeader->SizeOfRawData);

    return TRUE;
}

BOOL OniCompressInputFile(__in wchar_t *wcUncompressedFilePath, 
    __out LPVOID *lpCompressedBuffer, __out SIZE_T * szCompressedBufferSize) {
    COMPRESSOR_HANDLE chCompressor = NULL;
    PBYTE pbCompressedBuffer = NULL;
    PBYTE pbInputBuffer = NULL;
    HANDLE hInputFile = INVALID_HANDLE_VALUE;
    HANDLE hCompressedFile = INVALID_HANDLE_VALUE;
    BOOL bDeleteTargetFile = TRUE;
    BOOL bSuccess;
    SIZE_T _szCompressedDataSize, _szCompressedBufferSize;
    DWORD dwInputFileSize, dwByteRead, dwByteWritten;
    LARGE_INTEGER liFileSize;
   
    //  Open input file for reading, existing file only.
    hInputFile = CreateFileW(
        wcUncompressedFilePath,   //  Input file name
        GENERIC_READ,             //  Open for reading
        FILE_SHARE_READ,          //  Share for read
        NULL,                     //  Default security
        OPEN_EXISTING,            //  Existing file only
        FILE_ATTRIBUTE_NORMAL,    //  Normal file
        NULL);                    //  No attr. template

    do {
        if (hInputFile == INVALID_HANDLE_VALUE) {
            wprintf(L"[-] Cannot open \t%s\n", wcUncompressedFilePath);
            break;
        }

        //  Get input file size.
        bSuccess = GetFileSizeEx(hInputFile, &liFileSize);
        if ((!bSuccess) || (liFileSize.QuadPart > 0xFFFFFFFF)) {
            wprintf(L"[-] Cannot get input file size or file is larger than 4GB.\n");
            break;
        }
        dwInputFileSize = liFileSize.LowPart;

        //  Allocate memory for file content.
        pbInputBuffer = (PBYTE)malloc(dwInputFileSize);
        if (!pbInputBuffer) {
            wprintf(L"[-] Cannot allocate memory for uncompressed buffer.\n");
            break;
        }

        //  Read input file.
        bSuccess = ReadFile(hInputFile, pbInputBuffer, dwInputFileSize, &dwByteRead, NULL);
        if ((!bSuccess) || (dwByteRead != dwInputFileSize)) {
            wprintf(L"[-] Cannot read from \t%s\n", wcUncompressedFilePath);
            break;
        }

        //  Create an XpressHuff compressor.
        bSuccess = CreateCompressor(
            COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
            NULL,                           //  Optional allocation routine
            &chCompressor);                   //  Handle

        if (!bSuccess) {
            wprintf(L"[-] Cannot create a compressor %d.\n", GetLastError());
            break;
        }

        //  Query compressed buffer size.
        bSuccess = Compress(
            chCompressor,                  //  Compressor Handle
            pbInputBuffer,                 //  Input buffer, Uncompressed data
            dwInputFileSize,               //  Uncompressed data size
            NULL,                        //  Compressed Buffer
            0,                           //  Compressed Buffer size
            &_szCompressedBufferSize);      //  Compressed Data size

        //  Allocate memory for compressed buffer.
        if (!bSuccess) {
            DWORD ErrorCode = GetLastError();

            if (ErrorCode != ERROR_INSUFFICIENT_BUFFER) {
                wprintf(L"[-] Cannot compress data: %d.\n", ErrorCode);
                break;
            }

            pbCompressedBuffer = (PBYTE)calloc(1, _szCompressedBufferSize);
            if (!pbCompressedBuffer) {
                wprintf(L"[-] Cannot allocate memory for compressed buffer.\n");
                break;
            }
        }

        bSuccess = Compress(
            chCompressor,             //  Compressor Handle
            pbInputBuffer,            //  Input buffer, Uncompressed data
            dwInputFileSize,          //  Uncompressed data size
            pbCompressedBuffer,       //  Compressed Buffer
            _szCompressedBufferSize,   //  Compressed Buffer size
            &_szCompressedDataSize);   //  Compressed Data size

        if (!bSuccess) {
            wprintf(L"[-] Cannot compress data: %d\n", GetLastError());
            break;
        }

        *lpCompressedBuffer = pbCompressedBuffer;
        *szCompressedBufferSize = _szCompressedBufferSize;
        return TRUE;
        
    } while(0);

    if (chCompressor != NULL) {
        CloseCompressor(chCompressor);
    }

    if (pbCompressedBuffer) {
        free(pbCompressedBuffer);
    }

    if (pbInputBuffer) {
        free(pbInputBuffer);
    }

    if (hInputFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
    }

    if (hCompressedFile != INVALID_HANDLE_VALUE) {
        if (bDeleteTargetFile) {
            FILE_DISPOSITION_INFO fdi;
            fdi.DeleteFile = TRUE;     
            bSuccess = SetFileInformationByHandle(
                hCompressedFile,
                FileDispositionInfo,
                &fdi,
                sizeof(FILE_DISPOSITION_INFO));
            if (!bSuccess) {
                wprintf(L"[-] Cannot delete corrupted compressed file.\n");
            }
        }
        CloseHandle(hCompressedFile);
    }
    return FALSE;
}

int wmain(int argc, wchar_t** argv) {
    LPVOID lpCompressedBuffer;
    LPVOID lpDecompressedBuffer;
    SIZE_T szCompressedBufferSize;
    SIZE_T szDecompressedBufferSize;

    if (argc != 3) {
        wprintf(L"[!] Usage:\n\t%s <input_file_name> <packer_instance>\n", argv[0]);
        return 1;
    }

    OniCompressInputFile(argv[1], &lpCompressedBuffer, &szCompressedBufferSize);
    printf("[*] Compressed Buffer %p - 0x%08x\n", lpCompressedBuffer, szCompressedBufferSize);
    OniEmbedBufferInNewFileSection(lpCompressedBuffer, szCompressedBufferSize, (PCHAR)".rsrc", argv[2]);
    return 0;
}


