// PeLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include "OniLoader.h"
#include "PEB.h"

char* StrToLower(__in char* csStr) {
	for (int i = 0; csStr[i]; i++) {
		csStr[i] = tolower(csStr[i]);
	}
	return csStr;
}

DWORD OniFNV32(__in const char* cStr) {
	DWORD dwHash = FNV_OFFSET_32;
	unsigned int i;

	for (i = 0; i < strlen(cStr); i++) {
		dwHash = dwHash ^ (cStr[i]);			// xor next byte into the bottom of the hash
		dwHash = dwHash * FNV_PRIME_32;		// Multiply by prime number found to work well
	}
	return dwHash;
}

VOID OniMemCpy(__in VOID* vdDest, __in VOID* vdSrc, SIZE_T szDst) {
	unsigned int i;
	PBYTE pbSrc = (PBYTE)vdSrc;
	PBYTE pbDest = (PBYTE)vdDest;

	for (i = 0; i < szDst; i++) {
		pbDest[i] = pbSrc[i];
	}
}

VOID OniMemSet(__in VOID* vdSrc, __in SIZE_T szSrc) {
	unsigned int i;
	PBYTE pbStr = (PBYTE)vdSrc;

	for (i = 0; i < szSrc; i++) {
		pbStr[i] = '\0';
	}
}

HRESULT UnicodeToAnsi(__in LPCOLESTR pszW, __in LPSTR* ppszA) {
	ULONG cbAnsi;
	ULONG cCharacters;
	DWORD dwError;

	if (pszW == NULL) {
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)malloc(cbAnsi);
	if (NULL == *ppszA) {
		return E_OUTOFMEMORY;
	}

	if (!WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL)) {
		dwError = GetLastError();
		free(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}

BOOL OniGetLoaderSection(__in PONI_PARAM pOniParam) {
	HANDLE hMap = NULL;
	HANDLE hSelfMap = NULL;
	BOOL bLoaderSectionFound = FALSE;
	_PPEB pPeb;
	int i;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	
	hSelfMap = pOniParam->pGetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER)hSelfMap;
	pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hSelfMap + pDosHeader->e_lfanew);
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	
	for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (OniFNV32((char*)pSectionHeader[i].Name) == 0xff193085) {
			pOniParam->dwImageSize = pSectionHeader[i].SizeOfRawData;
			pOniParam->lpImageMapping = (LPVOID)((PBYTE)hSelfMap + pSectionHeader[i].VirtualAddress);
			bLoaderSectionFound = TRUE;
			break;
		}
	}
	
	do {
		if (!bLoaderSectionFound) {
			break;
		}

#ifdef _WIN32
		pPeb = (_PPEB)__readfsdword(0x30);
#else
		pPeb = (_PPEB)__readgsdword(0x30);
#endif

		pOniParam->lpLoaderBase = pPeb->lpImageBaseAddress;
		return TRUE;
		
	} while(0);
	
	return FALSE;
}

BOOL OniDecompressInputBuffer(__in PONI_PARAM pOniParam) {
	LPVOID lpCompressedBuffer;
	SIZE_T szCompressedBufferSize;
	DECOMPRESSOR_HANDLE hDecompressor = NULL;
	PBYTE pbDecompressedBuffer = NULL;
	SIZE_T _szDecompressedDataSize, _szDecompressedBufferSize;
	BOOL bSuccess;

	lpCompressedBuffer = pOniParam->lpImageMapping;
	szCompressedBufferSize = pOniParam->dwImageSize;

	bSuccess = pOniParam->pCreateDecompressor(
		COMPRESS_ALGORITHM_XPRESS_HUFF, 
		NULL,                          
		&hDecompressor);                 

	do {
		if (!bSuccess) {
			break;
		}

		bSuccess = pOniParam->pDecompress(
			hDecompressor,                
			lpCompressedBuffer,           
			szCompressedBufferSize,        
			NULL,                          
			0,                             
			&_szDecompressedBufferSize);   

		if (!bSuccess) {
			DWORD ErrorCode = GetLastError();

			if (ErrorCode != ERROR_INSUFFICIENT_BUFFER) {
				break;
			}

			pbDecompressedBuffer = (PBYTE)pOniParam->pLocalAlloc(LPTR, _szDecompressedBufferSize);
			if (!pbDecompressedBuffer) {
				break;
			}
		}

		bSuccess = pOniParam->pDecompress(
			hDecompressor,               
			lpCompressedBuffer,           
			szCompressedBufferSize,       
			pbDecompressedBuffer,         
			_szDecompressedBufferSize,    
			&_szDecompressedDataSize);    

		if (!bSuccess) {
			break;
		}

		pOniParam->lpImageMapping = pbDecompressedBuffer;
		pOniParam->dwImageSize = _szDecompressedBufferSize;
		pOniParam->pDosHeader = (PIMAGE_DOS_HEADER)pOniParam->lpImageMapping;

		if (!pOniParam->pDosHeader || 
			pOniParam->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			break;
		}

		pOniParam->pNtHeaders = (PIMAGE_NT_HEADERS)(
			(PBYTE)pOniParam->lpImageMapping + pOniParam->pDosHeader->e_lfanew);
		if (!pOniParam->pNtHeaders || 
			pOniParam->pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			break;
		}
		return TRUE;		
	} while(0);

	if (hDecompressor != NULL) {
		pOniParam->pCloseDecompressor(hDecompressor);
	}

	if (pbDecompressedBuffer) {
		pOniParam->pLocalFree(pbDecompressedBuffer);
	}
	return FALSE;
}

BOOL OniNeedSelfRelocation(__in PONI_PARAM pOniParam) {
	DWORD dwLdrBase;
	PIMAGE_DOS_HEADER pLdrDosHeader;
	PIMAGE_NT_HEADERS pLdrNtHeaders;

	dwLdrBase = (DWORD)pOniParam->pGetModuleHandle(NULL);
	
	do {
		if (!dwLdrBase) {
			break;
		}

		pLdrDosHeader = (PIMAGE_DOS_HEADER)dwLdrBase;
		pLdrNtHeaders = (PIMAGE_NT_HEADERS)(
			(PBYTE)dwLdrBase + pLdrDosHeader->e_lfanew);

		if (pLdrNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			break;
		}

		if ((pOniParam->pNtHeaders->OptionalHeader.ImageBase >= dwLdrBase)
			&& (pOniParam->pNtHeaders->OptionalHeader.ImageBase <
			(dwLdrBase + pLdrNtHeaders->OptionalHeader.SizeOfImage))) {
			return TRUE;
		}
	} while(0);
	
	return FALSE;
}

BOOL OniProcessIAT(__in DWORD dwImageBase, __in PONI_PARAM pOniParam) {
	BOOL bRet;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunkData;
	PIMAGE_THUNK_DATA pThunkDataOrig;
	PIMAGE_IMPORT_BY_NAME pImportByName;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	DWORD	dwFlError = 0;
	DWORD	dwTmp;
	PBYTE	pLibName;
	HMODULE hMod;

	pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	pNtHeaders = (PIMAGE_NT_HEADERS)(
		(PBYTE)dwImageBase + pDosHeader->e_lfanew);

	do {
		bRet = FALSE;
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (!pImportDesc) {
			break;
		}

		while ((pImportDesc->Name != 0) && (!dwFlError)) {
			pLibName = (PBYTE)(dwImageBase + pImportDesc->Name);

			if (pImportDesc->ForwarderChain != -1) {
				// TODO: implement IMPORT FORWARDING
			}

			hMod = pOniParam->pLoadLibraryA((LPCSTR)pLibName);
			if (!hMod) {
				dwFlError = 1;
				break;
			}

			pThunkData = (PIMAGE_THUNK_DATA)(dwImageBase +
				pImportDesc->FirstThunk);
			if (pImportDesc->Characteristics == 0) {
				// Apparently Borland Compilers do not produce a Hint Table
				pThunkDataOrig = pThunkData;
			} else {
				// Hint Table
				pThunkDataOrig = (PIMAGE_THUNK_DATA)(dwImageBase +
					pImportDesc->Characteristics);
			}

			while (pThunkDataOrig->u1.AddressOfData != 0) {
				if (pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					// Import via Export Ordinal
					PIMAGE_DOS_HEADER _pDosHdr;
					PIMAGE_NT_HEADERS _pNtHdr;

					_pDosHdr = (PIMAGE_DOS_HEADER)hMod;
					_pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)hMod + _pDosHdr->e_lfanew);
				
					pExportDir = (PIMAGE_EXPORT_DIRECTORY)
						((PBYTE)hMod + _pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					dwTmp = ((DWORD)((PBYTE)hMod + pExportDir->AddressOfFunctions)) + (((IMAGE_ORDINAL(pThunkDataOrig->u1.Ordinal) - pExportDir->Base)) * sizeof(DWORD));
					dwTmp = ((DWORD)((PBYTE)hMod + *(PDWORD)dwTmp));
					pThunkData->u1.Function = dwTmp;

				} else {
					pImportByName = (PIMAGE_IMPORT_BY_NAME)
						(dwImageBase + pThunkDataOrig->u1.AddressOfData);
					pThunkData->u1.Function = (DWORD)pOniParam->pGetProcAddress(hMod, (LPCSTR)pImportByName->Name);

					if (!pThunkData->u1.Function) {
						dwFlError = 1;
						break;
					}
				}
				pThunkDataOrig++;
				pThunkData++;
			}
			pImportDesc++;
		}
	} while (0);
	return (!dwFlError) ? TRUE : FALSE;
}

BOOL OniApplyBaseRelocations(__in DWORD dwImageBase, __in DWORD dwDelta) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	DWORD dwRelocationTableBase;
	DWORD dwRelocCount;
	PIMAGE_BASE_RELOCATION pBaseReloc;
	PIMAGE_RELOC pRelocEntry;

	pDosHeader = (PIMAGE_DOS_HEADER) dwImageBase;
	pNtHeaders = (PIMAGE_NT_HEADERS)(
		(PBYTE)dwImageBase + pDosHeader->e_lfanew);

	pBaseReloc = (PIMAGE_BASE_RELOCATION)
		(dwImageBase +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while (pBaseReloc->SizeOfBlock) {
		dwRelocationTableBase = dwImageBase + pBaseReloc->VirtualAddress;
		dwRelocCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		pRelocEntry = (PIMAGE_RELOC)((PBYTE)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		while (dwRelocCount--) {
			switch (pRelocEntry->type) {
			case IMAGE_REL_BASED_DIR64:
				*((PUINT_PTR)(dwRelocationTableBase + pRelocEntry->offset)) += dwDelta;
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*((PDWORD)(dwRelocationTableBase + pRelocEntry->offset)) += dwDelta;
				break;

			case IMAGE_REL_BASED_HIGH:
				*((PWORD)(dwRelocationTableBase + pRelocEntry->offset)) += HIWORD(dwDelta);
				break;

			case IMAGE_REL_BASED_LOW:
				*((PWORD)(dwRelocationTableBase + pRelocEntry->offset)) += LOWORD(dwDelta);
				break;

			case IMAGE_REL_BASED_ABSOLUTE: // usually used for padding
				break;
			}
			pRelocEntry += 1;
		}
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
	}
	return TRUE;
}

BOOL OniRelocateAndPivot(__in PONI_PARAM pOniParam, __in LPVOID pContFunc, __in PONI_PARAM pParam) {
	PIMAGE_DOS_HEADER pLdrDosHeader;
	PIMAGE_NT_HEADERS pLdrNtHeaders;
	LPVOID lpNewBase;
	LPVOID lpLdrBase;
	DWORD dwRelocatedContFuncAddr;
	DWORD dwRelDelta;
	VOID (__stdcall * pFptr)(PONI_PARAM);

	do {
		lpLdrBase = (LPVOID) pOniParam->pGetModuleHandle(NULL);
		if (!lpLdrBase) {
			break;
		}

		pLdrDosHeader = (PIMAGE_DOS_HEADER)lpLdrBase;
		pLdrNtHeaders = (PIMAGE_NT_HEADERS)(
			(PBYTE)lpLdrBase + pLdrDosHeader->e_lfanew);

		lpNewBase = pOniParam->pVirtualAlloc(NULL, pLdrNtHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!lpNewBase) {
			break;
		}

		pOniParam->lpLoaderRelocatedBase = lpNewBase;
		OniMemCpy(lpNewBase, lpLdrBase,
			pLdrNtHeaders->OptionalHeader.SizeOfImage);

		if (!OniProcessIAT((DWORD)lpNewBase, pOniParam)) {
			break;
		}

		dwRelDelta = (DWORD)((DWORD)lpNewBase - (DWORD)lpLdrBase);
		if (!OniApplyBaseRelocations((DWORD)lpNewBase, (DWORD)dwRelDelta)) {
			break;
		}

		pOniParam->lpLoaderBase = lpNewBase;

		dwRelocatedContFuncAddr = ((DWORD)pContFunc) - (DWORD)lpLdrBase;
		dwRelocatedContFuncAddr += (DWORD)lpNewBase;

		pFptr = (VOID (__stdcall*)(PONI_PARAM))dwRelocatedContFuncAddr;
		pFptr(pParam);

		return TRUE;
	} while(0);
	
	return FALSE;
}	

BOOL OniLoadImage(__in PONI_PARAM pOniParam) {
	BOOL bRet = FALSE;
	DWORD dwCentinel;
	MEMORY_BASIC_INFORMATION mi;
	PIMAGE_SECTION_HEADER	pSectionHeader;

	if (!pOniParam) {
		return bRet;
	}

	do {
		dwCentinel = (DWORD)pOniParam->lpLoaderBase;
		while (pOniParam->pVirtualQuery((LPVOID)dwCentinel, &mi, sizeof(mi))) {
			if (mi.State == MEM_FREE) {
				break;
			}
			dwCentinel += mi.RegionSize;
		}

		if ((pOniParam->pNtHeaders->OptionalHeader.ImageBase >=
			(DWORD)pOniParam->lpLoaderBase) &&
			(pOniParam->pNtHeaders->OptionalHeader.ImageBase < dwCentinel)) {
			if (pOniParam->pNtUnmapViewOfSection) {
				pOniParam->pNtUnmapViewOfSection(pOniParam->pGetCurrentProcess(), pOniParam->lpLoaderBase);
			}
		}

		pOniParam->dwImageBase = (DWORD)pOniParam->pVirtualAlloc((LPVOID)pOniParam->pNtHeaders->OptionalHeader.ImageBase,
			pOniParam->pNtHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		
		if (!pOniParam->dwImageBase) {
			if (!pOniParam->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
				pOniParam->dwImageBase = (DWORD)pOniParam->pNtHeaders->OptionalHeader.ImageBase;
			} else {
				pOniParam->dwImageBase = (DWORD)pOniParam->pVirtualAlloc(NULL,
					pOniParam->pNtHeaders->OptionalHeader.SizeOfImage,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}
		}

		if (!pOniParam->dwImageBase) {
			break;
		}
		
		OniMemCpy((LPVOID)pOniParam->dwImageBase, (LPVOID)pOniParam->lpImageMapping,
			pOniParam->pNtHeaders->OptionalHeader.SizeOfHeaders);

		pSectionHeader = IMAGE_FIRST_SECTION(pOniParam->pNtHeaders);
		for (dwCentinel = 0; dwCentinel < pOniParam->pNtHeaders->FileHeader.NumberOfSections; dwCentinel++) {			
			OniMemCpy((LPVOID)((PBYTE)pOniParam->dwImageBase + pSectionHeader[dwCentinel].VirtualAddress),
				(LPVOID)((PBYTE)pOniParam->lpImageMapping + pSectionHeader[dwCentinel].PointerToRawData),
				pSectionHeader[dwCentinel].SizeOfRawData
			);
		}
		bRet = TRUE;
	} while (0);
	return bRet;
}

BOOL OniApplyRelocations(__in PONI_PARAM pOniParam) {
	DWORD dwRelDelta;

	if (pOniParam->dwImageBase == pOniParam->pNtHeaders->OptionalHeader.ImageBase) {
		return TRUE;
	}

	if (!pOniParam->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		return FALSE;
	}

	dwRelDelta = pOniParam->dwImageBase - pOniParam->pNtHeaders->OptionalHeader.ImageBase;
	return OniApplyBaseRelocations(pOniParam->dwImageBase, dwRelDelta);
}

BOOL OniRunImage(__in PONI_PARAM pOniParam) {
	DWORD dwOld;
	DWORD dwEP;
	_PPEB pPeb;
	VOID (__stdcall * fpEntry)();

	if (!pOniParam->pVirtualProtect((LPVOID)pOniParam->dwImageBase,
		pOniParam->pNtHeaders->OptionalHeader.SizeOfImage,
		PAGE_EXECUTE_READWRITE, &dwOld)) {
		return FALSE;
	}

#ifdef _WIN32
	pPeb = (_PPEB)__readfsdword(0x30);
#else
	pPeb = (_PPEB)__readgsdword(0x30);
#endif
	pPeb->lpImageBaseAddress = (LPVOID)pOniParam->dwImageBase;
	
	dwEP = pOniParam->dwImageBase + pOniParam->pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	fpEntry = (VOID(__stdcall*)())dwEP;
	fpEntry();
	
	return TRUE;
}

BOOL OniLoadAndRunImage(__in PONI_PARAM pOniParam) {
	do {
		if (!OniLoadImage(pOniParam)) {
			break;
		} 
		if (!OniProcessIAT(pOniParam->dwImageBase, pOniParam)) {
			break;
		}
		if (!OniApplyRelocations(pOniParam)) {
			break;
		}
		if (!OniRunImage(pOniParam)) {
			break;
		}
		return TRUE;
	} while(0);

	return FALSE;
}

LPVOID OniFindDllExport(__in LPVOID dll_base, __in DWORD dwFNVHash) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	DWORD dwExportDescriptorOffset;
	PIMAGE_EXPORT_DIRECTORY pExportTable;
	PDWORD pdwNameTable;
	PWORD pwOrdinalTable;
	PDWORD pdwFuncTable;
	unsigned int i;

	pDosHeader = (PIMAGE_DOS_HEADER)dll_base;
	pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dll_base + pDosHeader->e_lfanew);

	dwExportDescriptorOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dll_base + dwExportDescriptorOffset);

	// - The i-th element of the name table contains the export name
	// - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
	pdwNameTable = (PDWORD)((PBYTE)dll_base + pExportTable->AddressOfNames);
	pwOrdinalTable = (PWORD)((PBYTE)dll_base + pExportTable->AddressOfNameOrdinals);
	pdwFuncTable = (PDWORD)((PBYTE)dll_base + pExportTable->AddressOfFunctions);

	for ( i = 0; i < pExportTable->NumberOfNames; ++i) {
		PCHAR strFuncName = (PCHAR)((PBYTE)dll_base + pdwNameTable[i]);
		LPVOID pFuncVaddr = (LPVOID)((PBYTE)dll_base + pdwFuncTable[pwOrdinalTable[i]]);
		DWORD dwHash = OniFNV32(strFuncName);
		if (dwHash == dwFNVHash) {
			return pFuncVaddr;
		}
	}
	return NULL;
}

LPVOID OniFindDllBase(__in DWORD dwFNVHash) {
	_PPEB pPeb;
	PPEB_LDR_DATA pLoader;
	PLIST_ENTRY pHead;
	PLIST_ENTRY pCurr;
	DWORD dwHash;

#ifdef _WIN32
	pPeb = (_PPEB)__readfsdword(0x30);
#else
	pPeb = (_PPEB)__readgsdword(0x30);
#endif
	pLoader = pPeb->pLdr;
	pHead = &pLoader->InMemoryOrderModuleList;
	pCurr = pHead->Flink;

	do {
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(pCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		char* dllName;
		UnicodeToAnsi(dllEntry->BaseDllName.Buffer, &dllName);
		dwHash = OniFNV32(StrToLower(dllName));
		free(dllName);

		if (dwHash == dwFNVHash) {
			return (LPVOID)dllEntry->DllBase;
		}
		pCurr = pCurr->Flink;
	} while (pCurr != pHead);

	return NULL;
}

BOOL OniResolveDynamicImports(__in PONI_PARAM pOniParam) {
	CHAR pcsCabinetDll[] = { 'C', 'A', 'B', 'I', 'N', 'E', 'T', '.', 'D', 'L', 'L', '\0' };

	do {
		if (!(pOniParam->pKernel32Base = OniFindDllBase(0xa3e6f6c3))) {
			break;
		}
		if (!(pOniParam->pGetProcAddress = 
			(GetProcAddressProto)OniFindDllExport(pOniParam->pKernel32Base, 0xf8f45725))) {
			break;
		}
		if (!(pOniParam->pGetModuleHandle = 
			(GetModuleHandleProto)OniFindDllExport(pOniParam->pKernel32Base, 0xe463da3c))) {
			break;
		}
		if (!(pOniParam->pVirtualProtect = 
			(VirtualProtectProto)OniFindDllExport(pOniParam->pKernel32Base, 0x820621f3))) {
			break;
		}
		if (!(pOniParam->pVirtualAlloc = 
			(VirtualAllocProto)OniFindDllExport(pOniParam->pKernel32Base, 0x3285501))) {
			break;
		}
		if (!(pOniParam->pGetCurrentProcess = 
			(GetCurrentProcessProto)OniFindDllExport(pOniParam->pKernel32Base, 0x6dd8a845))) {
			break;
		}
		if (!(pOniParam->pVirtualQuery = 
			(VirtualQueryProto)OniFindDllExport(pOniParam->pKernel32Base, 0xbe4d5ef8))) {
			break;
		}
		if (!(pOniParam->pLoadLibraryA = 
			(LoadLibraryAProto)OniFindDllExport(pOniParam->pKernel32Base, 0x53b2070f))) {
			break;
		}
		if (!(pOniParam->pLocalAlloc = 
			(LocalAllocProto)OniFindDllExport(pOniParam->pKernel32Base, 0xc2c33c3d))) {
			break;
		}
		if (!(pOniParam->pLocalFree = 
			(LocalFreeProto)OniFindDllExport(pOniParam->pKernel32Base, 0xbf0306f6))) {
			break;
		}
		if (!(pOniParam->pCabinetBase = pOniParam->pLoadLibraryA(pcsCabinetDll))) {
			break;
		}
		if (!(pOniParam->pCreateDecompressor =
			(CreateDecompressorProto)OniFindDllExport(pOniParam->pCabinetBase, 0x6b2156a7))) {
			break;
		}
		if (!(pOniParam->pDecompress = 
			(DecompressProto)OniFindDllExport(pOniParam->pCabinetBase, 0x1bfe3882))) {
			break;
		}
		if (!(pOniParam->pCloseDecompressor = 
			(CloseDecompressorProto)OniFindDllExport(pOniParam->pCabinetBase, 0x50ad9c01))) {
			break;
		}
		if (!(pOniParam->pNtUnmapViewOfSection = 
			(NtUnmapViewOfSectionProto)OniFindDllExport(OniFindDllBase(0xa62a3b3b), 0x2620a5cc))) {
			break;
		}
		return TRUE;
	} while (0);
	
	return FALSE;
}

int wmain(int argc, wchar_t* argv[]) {
	ONI_PARAM oniParam;

	OniMemSet(&oniParam, sizeof(oniParam));
	if (!OniResolveDynamicImports(&oniParam) || 
		!OniGetLoaderSection(&oniParam) || 
		!OniDecompressInputBuffer(&oniParam)) {
		return 1;
	}

	if (OniNeedSelfRelocation(&oniParam)) {
		return OniRelocateAndPivot(&oniParam, OniLoadAndRunImage, &oniParam);
	}
	return OniLoadAndRunImage(&oniParam);
}

