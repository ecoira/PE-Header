#include "stdafx.h"
#include<windows.h>
#include<stdio.h>
#include<stdlib.h>

IMAGE_DOS_HEADER myDosHeader;
IMAGE_NT_HEADERS myNtHeader;
IMAGE_FILE_HEADER myFileHeader;
IMAGE_OPTIONAL_HEADER myOptionHeader;
IMAGE_SECTION_HEADER* pmySectionHeader;

LONG e_lfanew;
int SectionCount;
int Signature;

int main(int argc, char* argv[])
{
	FILE* pfile;
	fopen_s(&pfile, "notepad.exe", "rb");
	/*
	if (fopen_s(&pfile, "D:\\notepad.exe", "rb") == NULL)
	{
		printf("fail open file!");
		exit(0);
	}*/

	if (pfile == NULL)
		printf("%d", GetLastError());

	//DOS头部分
	printf("================IMAGE_DOS_HEADER================\n");
	fread(&myDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pfile);
	printf("WORD  e_magic:				%04X\n", myDosHeader.e_magic);
	printf("DWORD e_lfanew:				%08X\n\n", myDosHeader.e_lfanew);
	e_lfanew = myDosHeader.e_lfanew;

	//NT头部分
	printf("================IMAGE_NT_HEADER================\n");
	fseek(pfile, e_lfanew, 0);
	fread(&myNtHeader, sizeof(IMAGE_NT_HEADERS), 1, pfile);
	printf("DWORD Signature:			%08x\n\n", myNtHeader.Signature);
	Signature = myNtHeader.Signature;
	if (Signature != 0x4550)    //判断是否为PE文件
	{
		exit(0);
	}

	//FILE头部分
	printf("================IMAGE_FILE_HEADER================\n");
	fseek(pfile, (e_lfanew + sizeof(DWORD)), 0);
	fread(&myFileHeader, sizeof(IMAGE_FILE_HEADER), 1, pfile);
	printf("WORD Machine:				%04X\n", myFileHeader.Machine);
	printf("WORD NumberOfSections:			%04X\n", myFileHeader.NumberOfSections);
	printf("DWORD TimeDateStamp:			%08X\n", myFileHeader.TimeDateStamp);
	printf("DWORD PointerToSymbolTable:		%08X\n", myFileHeader.PointerToSymbolTable);
	printf("DWORD NumberOfSymbols:			%08X\n", myFileHeader.NumberOfSymbols);
	printf("WORD SizeOfOptionalHeader:		%04X\n", myFileHeader.SizeOfOptionalHeader);
	printf("WORD Characteristics:			%04X\n\n", myFileHeader.Characteristics);
	SectionCount = myFileHeader.NumberOfSections;

	//OPTIONAL头部分
	printf("================IMAGE_OPTIONAL_HEADER================\n");
	fseek(pfile, (e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), 0);
	fread(&myOptionHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, pfile);
	printf("WORD Magic:				%04X\n", myOptionHeader.Magic);
	printf("BYTE MajorLinkerVersion:		%02X\n", myOptionHeader.MajorLinkerVersion);
	printf("BYTE MinorLinkerVersion:		%02X\n", myOptionHeader.MinorLinkerVersion);
	printf("DWORD SizeOfCode:			%08X\n", myOptionHeader.SizeOfCode);
	printf("DWORD SizeOfInitializedData:		%08X\n", myOptionHeader.SizeOfInitializedData);
	printf("DWORD SizeOfUninitializedData:		%08X\n", myOptionHeader.SizeOfUninitializedData);
	printf("DWORD AddressOfEntryPoint:		%08X\n", myOptionHeader.AddressOfEntryPoint);
	printf("DWORD BaseOfCode:			%08X\n", myOptionHeader.BaseOfCode);
	printf("DWORD BaseOfData:			%08X\n", myOptionHeader.BaseOfData);
	printf("DWORD ImageBase:			%08X\n", myOptionHeader.ImageBase);
	printf("DWORD SectionAlignment:			%08X\n", myOptionHeader.SectionAlignment);
	printf("DWORD FileAlignment:			%08X\n", myOptionHeader.FileAlignment);
	printf("WORD MajorOperatingSystemVersion:	%04X\n", myOptionHeader.MajorOperatingSystemVersion);
	printf("WORD MinorOperatingSystemVersion:	%04X\n", myOptionHeader.MinorOperatingSystemVersion);
	printf("WORD MajorImageVersion:			%04X\n", myOptionHeader.MajorImageVersion);
	printf("WORD MinorImageVersion:			%04X\n", myOptionHeader.MinorImageVersion);
	printf("WORD MajorSubsystemVersion:		%04X\n", myOptionHeader.MajorSubsystemVersion);
	printf("WORD MinorSubsystemVersion:		%04X\n", myOptionHeader.MinorSubsystemVersion);
	printf("DWORD Win32VersionValue:		%08X\n", myOptionHeader.Win32VersionValue);
	printf("DWORD SizeOfImage:			%08X\n", myOptionHeader.SizeOfImage);
	printf("DWORD SizeOfHeaders:			%08X\n", myOptionHeader.SizeOfHeaders);
	printf("DWORD CheckSum:				%08X\n", myOptionHeader.CheckSum);
	printf("WORD Subsystem:				%04X\n", myOptionHeader.Subsystem);
	printf("WORD DllCharacteristics:		%04X\n", myOptionHeader.DllCharacteristics);
	printf("DWORD SizeOfStackReserve:		%08X\n", myOptionHeader.SizeOfStackReserve);
	printf("DWORD SizeOfStackCommit:		%08X\n", myOptionHeader.SizeOfStackCommit);
	printf("DWORD SizeOfHeapReserve:		%08X\n", myOptionHeader.SizeOfHeapReserve);
	printf("DWORD SizeOfHeapCommit:			%08X\n", myOptionHeader.SizeOfHeapCommit);
	printf("DWORD LoaderFlags:			%08X\n", myOptionHeader.LoaderFlags);
	printf("DWORD NumberOfRvaAndSizes:		%08X\n\n", myOptionHeader.NumberOfRvaAndSizes);

	//节表目录
	printf("================IMAGE_OPTIONAL_HEADER================\n");
	pmySectionHeader = (IMAGE_SECTION_HEADER*)calloc(SectionCount, sizeof(IMAGE_SECTION_HEADER));
	fseek(pfile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), 0);
	fread(pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), SectionCount, pfile);
	for (int i = 0; i < SectionCount; i++, pmySectionHeader++)
	{
		printf("BYTE Name:				%s\n", pmySectionHeader->Name);
		printf(":DWORD PhysicalAddress			%08X\n", pmySectionHeader->Misc.PhysicalAddress);
		printf(":DWORD VirtualSize			%08X\n", pmySectionHeader->Misc.VirtualSize);
		printf(":DWORD VirtualAddress			%08X\n", pmySectionHeader->VirtualAddress);
		printf(":DWORD SizeOfRawData			%08X\n", pmySectionHeader->SizeOfRawData);
		printf(":DWORD PointerToRawData			%08X\n", pmySectionHeader->PointerToRawData);
		printf(":DWORD PointerToRelocations		%08X\n", pmySectionHeader->PointerToRelocations);
		printf(":DWORD PointerToLinenumbers		%08X\n", pmySectionHeader->PointerToLinenumbers);
		printf(":WORD NumberOfRelocations		%04X\n", pmySectionHeader->NumberOfRelocations);
		printf(":WORD NumberOfLinenumbers		%04X\n", pmySectionHeader->NumberOfLinenumbers);
		printf(":DWORD Characteristics			%08X\n\n", pmySectionHeader->Characteristics);

	}

	if (pmySectionHeader != NULL)
	{
		pmySectionHeader = NULL;
		free(pmySectionHeader);
		
	}

	fclose(pfile);
	return 0;
}