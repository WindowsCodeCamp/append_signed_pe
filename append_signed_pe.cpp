// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <windows.h>
#include <stdio.h>
#include <string>
#include "imagehlp.h"
#pragma comment(lib, "Imagehlp.lib")


// 追加的内容
BOOL AppendSignExeData(const std::wstring& f, const std::string& data) {
	HANDLE fileHandle = CreateFileW(f.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		return 0;
	}

	HANDLE mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (mapHandle == NULL) {
		CloseHandle(fileHandle);
		return 0;
	}

	LPBYTE lpBaseAddress = (LPBYTE)MapViewOfFile(mapHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (lpBaseAddress == NULL) {
		CloseHandle(mapHandle);
		CloseHandle(fileHandle);
		return 0;
	}

	PIMAGE_DOS_HEADER dosHead = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS32 ntHead = (PIMAGE_NT_HEADERS32)(lpBaseAddress + dosHead->e_lfanew);
	PIMAGE_NT_HEADERS64 ntHead64 = (PIMAGE_NT_HEADERS64)(lpBaseAddress + dosHead->e_lfanew);
	if (dosHead->e_magic != IMAGE_DOS_SIGNATURE || ntHead->Signature != IMAGE_NT_SIGNATURE) {
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(mapHandle);
		CloseHandle(fileHandle);
		return 0;
	}

	// 判断是否是x64
	BOOL isX64 = (ntHead->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC);
	PIMAGE_DATA_DIRECTORY idd = NULL;
	if (isX64) {
		idd = &ntHead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}
	else {
		idd = &ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}
	if (idd->Size == 0 || idd->VirtualAddress == 0) {
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(mapHandle);
		CloseHandle(fileHandle);
		return 0;
	}

	DWORD writeSize = (DWORD)(data.size() + 7) / 8 * 8;

	// 修改Security.Size
	idd->Size += writeSize + 8;

	UnmapViewOfFile(lpBaseAddress);
	CloseHandle(mapHandle);

	SetFilePointer(fileHandle, 0, 0, FILE_END);
	DWORD size = 0;
	WriteFile(fileHandle, (LPCVOID)data.c_str(), (DWORD)data.length(), &size, NULL);
	if (size != data.length()) {
		CloseHandle(fileHandle);
		return 0;
	}

	// 补上多余的几个
	if (writeSize > data.size()) {
		for (DWORD i = 0; i < writeSize - data.size(); i++) {
			size = 0;
			WriteFile(fileHandle, "\0", 1, &size, NULL);
			if (size != 1) {
				CloseHandle(fileHandle);
				return 0;
			}
		}
	}

	size = 0;
	UINT64 len = (UINT64)data.size();
	WriteFile(fileHandle, (LPCVOID)&len, 8, &size, NULL);
	if (size != 8) {
		CloseHandle(fileHandle);
		return 0;
	}

	// 修改校验和（因为有些杀软会将校验和不对的程序报毒）
	mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (mapHandle == NULL) {
		CloseHandle(fileHandle);
		return 0;
	}
	lpBaseAddress = (LPBYTE)MapViewOfFile(mapHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (lpBaseAddress == NULL) {
		CloseHandle(mapHandle);
		CloseHandle(fileHandle);
		return 0;
	}

	DWORD file_len = GetFileSize(fileHandle, NULL);
	if (file_len == INVALID_FILE_SIZE) {
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(mapHandle);
		CloseHandle(fileHandle);
		return 0;
	}

	// 这个PIMAGE_NT_HEADERS设计的非常巧妙，无论是32还是64，CheckSum的偏移是一样的，所以这个代码不需要改，都兼容
	DWORD oldCheckSum, newCheckSum;
	PIMAGE_NT_HEADERS peHeader = CheckSumMappedFile((PVOID)lpBaseAddress, file_len, &oldCheckSum, &newCheckSum);
	peHeader->OptionalHeader.CheckSum = newCheckSum;

	UnmapViewOfFile(lpBaseAddress);
	CloseHandle(mapHandle);
	CloseHandle(fileHandle);
	return TRUE;
}

// 成功返回追加内容，失败返回空字符串
std::string ReadSignExeData(const std::wstring& f) {
	HANDLE fileHandle = CreateFileW(f.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		return "";
	}
	DWORD ret = SetFilePointer(fileHandle, -8, 0, FILE_END);
	if (ret == INVALID_SET_FILE_POINTER) {
		CloseHandle(fileHandle);
		return "";
	}

	UINT64 len = 0;
	DWORD size = 0;
	ReadFile(fileHandle, &len, 8, &size, NULL);
	if (size != 8) {
		CloseHandle(fileHandle);
		return "";
	}

	// 若是大于200MB, 当作出错处理
	if (len > 1024 * 1024 * 200) {
		CloseHandle(fileHandle);
		return "";
	}

	LONG readSize = (LONG)(len + 7) / 8 * 8;
	ret = SetFilePointer(fileHandle, -(readSize + 8), 0, FILE_END);
	if (ret == INVALID_SET_FILE_POINTER) {
		CloseHandle(fileHandle);
		return "";
	}

	size = 0;
	std::string result;
	result.resize((size_t)len);
	ReadFile(fileHandle, (LPVOID)result.c_str(), (DWORD)len, &size, NULL);
	CloseHandle(fileHandle);

	if (size != len) {
		return "";
	}
	return result;
}

int main()
{
	std::string data = "hello,world---";
	BOOL xxx = AppendSignExeData(L"D:\\pe.exe", data);
	if (xxx) {
		auto read_data = ReadSignExeData(L"D:\\pe.exe");
		if (read_data != data) {
			printf("ERROR!!!\r\n");
		}
		else {
			printf("OK!!!\r\n");
		}
	}
	else {
		printf("ERROR!!!\r\n");
	}

	return 0;
}
