#include<Windows.h>
#include<stdio.h>
//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

typedef struct MyOldDataAndShellCodeStruct {
	IMAGE_DATA_DIRECTORY DataDirectory[16];
	IMAGE_SECTION_HEADER EndSectionHeader;
	DWORD AddressOfEntryPoint;
	DWORD ImageBase;
	BYTE ShellCode;
}MY_OLD_DATA_AND_SHELL_CODE_STRUCT,*PMY_OLD_DATA_AND_SHELL_CODE_STRUCT;

//默认InLoadOrderModuleList双向链中的第一个（上一个）_LDR_DATA_TABEL_ENTRY结构，指向的模块为exe本身。
void Pe_selfStarting_Shell() {
	
	unsigned long HashKernel32 = 0x330;//KERNEL32.DLL字符串累加哈希的值
	wchar_t* pKernelName = 0;
	unsigned long pKernel32Module = 0;
	unsigned long pExeModule = 0;//默认InLoadOrderModuleList双向链中的第一个（上一个）_LDR_DATA_TABEL_ENTRY结构，指向的模块为exe本身。
	unsigned char* pPeb = 0;
	//MessageBox(0, 0, 0, 0);
//遍历PEB结构中的LDR结构，找到KERNEL32.DLL在内存中的基址
	_asm {
		pushad;
		mov eax, fs: [0x30] ;//fs寄存器代表TEB，偏移0x30指向PEB
		mov pPeb, eax;
		mov eax, [eax + 0xc];//指向_PEB_LDR_DATA

		mov ebx, eax;
		add ebx, 0xc;//这个是InLoadOrderModuleList双向链的起始位置，用于判断是否循环回来的

		mov eax, [eax + 0xc];//现在eax指向InLoadOrderModuleList双向链中的第一个（上一个）_LDR_DATA_TABEL_ENTRY结构
	//**** start ********
		push eax;//此时的eax指向指向InLoadOrderModuleList双向链中的第一个（上一个）_LDR_DATA_TABEL_ENTRY结构
				 //可以理解为倒数第一个，因为List_Entry是一个双向链表，此时分别指向上一个和下一个_LDR_DATA_TABEL_ENTRY结构
				 //一般倒数第一个加载的模块为exe本身。
		mov eax, [eax + 0x18];//保存一份自己exe模块再内存中的基址
		mov pExeModule, eax;
		pop eax;
	//**** end ********
		//开始遍历双向链，直到找到Kenel32.dll
	Addr1:

		mov edi, [eax + 0x30];//取BaseDLLName（UNICODE_STRING）中的第5字节，pBuffer，指向模块名
		
		//******start 下面是进行HASH算法（将BaseDllName中的所有字符挨个累加，得到hash值（相对唯一）。）
		mov ecx, 12 * 2;//unicode字符串，所以乘2
		xor esi, esi;
	
	NextKernel32:
		xor ebx, ebx;
		add bl, byte ptr[edi + ecx - 1];
		add esi, ebx;
		loop NextKernel32;
		//比较最后得到的hash值，相等则证明找到KERNEL32.DLL的模块	
		cmp esi, HashKernel32;
		je End;
		//******end

		mov eax, [eax];
		cmp eax, ebx;
		jne Addr1;
	End:
		mov eax, [eax + 0x18];//_LDR_DATA_TABLE_ENTRY中偏移0x18->DLLbase,指向该模块基地址，即KERNEL32.dll
		mov pKernel32Module, eax;
		mov pKernelName, edi;
		nop;
		nop;
		popad;
	}

//解析KERNEL32的pe结构，获取GetProcAddress函数地址。
	PIMAGE_DOS_HEADER pKernel32DosHeader = (PIMAGE_DOS_HEADER)pKernel32Module;
	PIMAGE_NT_HEADERS32 pKernel32NtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pKernel32DosHeader + pKernel32DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pKernel32FileHeader = (PIMAGE_FILE_HEADER)((DWORD)pKernel32NtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pKernel32OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pKernel32FileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_DATA_DIRECTORY pKernel32DataDirectory = (PIMAGE_DATA_DIRECTORY)pKernel32OptionalHeader->DataDirectory;
	PIMAGE_EXPORT_DIRECTORY pKernel32ModuleExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pKernel32Module+pKernel32DataDirectory[0].VirtualAddress);
	
	typedef FARPROC(WINAPI* PGETPROCADDRESS)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
	PGETPROCADDRESS pGetProcAddress = NULL;
	unsigned long HashGetProcAddress = 0x57A;//GetProcAddress字符串累加哈希的值,Ascll字符串，共14个字符
//遍历导出表，找到GetProcAddress函数，以函数名导出。Ascll字符串
	unsigned long* pAddressOfNames = (unsigned long*)(pKernel32Module + pKernel32ModuleExportDirectory->AddressOfNames);//导出函数名称表，你们存储的是指向导出函数名称的RVA
	DWORD Offset_Of_AddressOfNames = 0;//记录GetProcAddress函数在函数名称表中的偏移序号


	while (pAddressOfNames) {

		char* pNameOfFunction = (char*)(pKernel32Module + *pAddressOfNames);
		//对函数名成进行自定义hash计算，（即累加求值），i<14因为GetProcAddress函数名称为14个字符
		unsigned long HashNameOfFunction = 0;

		for (int i = 0; *(pNameOfFunction + i) != 0; i++) {
		/*
			_asm {
				_emit 0xCC;
				_emit 0xcc;
				_emit 0xcc;
				_emit 0xcc;
				_emit 0xcc;
				_emit 0xcc;
				_emit 0xcc;
				_emit 0xcc;
			}
		*/
			HashNameOfFunction += *(pNameOfFunction+i);
		}

		if (HashNameOfFunction == HashGetProcAddress) {
			break;
		}
		pAddressOfNames++;
		Offset_Of_AddressOfNames++;
	}

	unsigned short* pAddressOfNameOrdinals = (unsigned short*)(pKernel32Module + pKernel32ModuleExportDirectory->AddressOfNameOrdinals);
	unsigned long Ordinal_Of_AddressOfFunctions = (unsigned long)*(pAddressOfNameOrdinals + Offset_Of_AddressOfNames);//在函数序号表里取出的序号
	unsigned long* pAddressOfFunctions = (unsigned long*)(pKernel32Module + pKernel32ModuleExportDirectory->AddressOfFunctions);
	pGetProcAddress = (PGETPROCADDRESS)(pKernel32Module + *(pAddressOfFunctions+Ordinal_Of_AddressOfFunctions));


//通过pGetProcAddress获取LoadLibrary函数的地址
	typedef HMODULE(WINAPI* PLOADLIBRARY)(_In_ LPCSTR lpLibFileName);
	char szLoadLibraryA[] = { 0xd5,0xf6,0xf8,0xfd,0xd5,0xf0,0xfb,0xeb,0xf8,0xeb,0xe0,0xd8,0 };//{ 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	for (int i = 0; szLoadLibraryA[i]; i++) {
		szLoadLibraryA[i] ^= 0x99;
	}
	PLOADLIBRARY pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)pKernel32Module, szLoadLibraryA);

	
//加载USER32.dll,获取MessageBoxA函数地址
	char szUser32[] = { 0xcc,0xca,0xdc,0xcb,0xaa,0xab,0xb7,0xfd,0xf5,0xf5,0 };// { 'U','S','E','R','3','2','.','d','l','l',0 };
	for (int i = 0; szUser32[i]; i++) {
		szUser32[i] ^= 0x99;
	}
	HMODULE pUser32 = pLoadLibrary(szUser32);

	typedef int(WINAPI* PMESSAGEBOXW) (_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
	char szMessageBoxW[] = { 0xd4,0xfc,0xea,0xea,0xf8,0xfe,0xfc,0xdb,0xf6,0xe1,0xce,0 }; //{ 'M','e','s','s','a','g','e','B','o','x','W',0 };
	for (int i = 0; szMessageBoxW[i]; i++) {
		szMessageBoxW[i] ^= 0x99;
	}
	PMESSAGEBOXW pMessageBoxW = (PMESSAGEBOXW)pGetProcAddress(pUser32, szMessageBoxW);
	//pMessageBoxW(0, pKernelName, 0, 0);

	
	/*
	_asm {
		pushad;
		mov eax, fs: [0x30] ;//fs寄存器代表TEB，偏移0x30指向PEB
		mov eax, [eax + 0xc];//指向_PEB_LDR_DATA

		mov ebx, eax;
		add ebx, 0xc;//这个是InLoadOrderModuleList双向链的起始位置，用于判断是否循环回来的

		mov eax, [eax + 0xc];//现在eax指向InLoadOrderModuleList双向链中的第一个_LDR_DATA_TABEL_ENTRY结构

		//开始遍历双向链，直到找到Kenel32.dll
	Addr2:

		mov edi, [eax + 0x30];//取BaseDLLName（UNICODE_STRING）中的第5字节，pBuffer，指向模块名

		push eax;
		push 0;
		push 0;
		push edi;
		push 0;
		call pMessageBoxW;
		pop eax;

		mov eax, [eax];
		cmp eax, ebx;
		jne Addr2;
	}
	*/
	
//解析PE结构 pExeModule
	PIMAGE_DOS_HEADER pExeDosHeader = (PIMAGE_DOS_HEADER)pExeModule;
	PIMAGE_NT_HEADERS32 pExeNtHeader = (PIMAGE_NT_HEADERS32)(pExeModule + pExeDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pExeFileheader = (PIMAGE_FILE_HEADER)((DWORD)pExeNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pExeOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pExeFileheader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_DATA_DIRECTORY pExeDataDirectory = (PIMAGE_DATA_DIRECTORY)(pExeOptionalHeader->DataDirectory);
	
//从备份的数据里提取原始目录项，进行复原
	//复原的时候，涉及内存写操作，要改变内存页属性，最好小范围改，改了之后还原
	typedef BOOL(WINAPI* PVIRTUALPROTECT)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
	char szVirtualProtect[] = { 0xcf,0xf0,0xeb,0xed,0xec,0xf8,0xf5,0xc9,0xeb,0xf6,0xed,0xfc,0xfa,0xed,0 }; //{ 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
	for (int i = 0; szVirtualProtect[i]; i++) {
		szVirtualProtect[i] ^= 0x99;
	}
	PVIRTUALPROTECT pVirtualProtect = (PVIRTUALPROTECT)pGetProcAddress((HMODULE)pKernel32Module, szVirtualProtect);

	//定位外壳结构的位置,+4是应为sizeof(MyOldDataAndShellCodeStruct)包含了最后一个成员ShellCode的4字节。
	PMY_OLD_DATA_AND_SHELL_CODE_STRUCT pOldDataAndShellCodeStruct = (PMY_OLD_DATA_AND_SHELL_CODE_STRUCT)(pExeModule + pExeOptionalHeader->AddressOfEntryPoint - sizeof(MyOldDataAndShellCodeStruct) + 4);
	
	DWORD SourceAddress = 0;
	DWORD DestinationAddress = 0;
	DWORD CopySize = 0;

	SourceAddress = (DWORD)pOldDataAndShellCodeStruct->DataDirectory;
	DestinationAddress = (DWORD)pExeOptionalHeader->DataDirectory;
	CopySize = sizeof(pOldDataAndShellCodeStruct->DataDirectory);
	//写之前改内存页属性为可读可写
	DWORD lpflOldProtect = 0;
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, PAGE_READWRITE, &lpflOldProtect);
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
	//写之后复原。
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, lpflOldProtect, &lpflOldProtect);

	
//复原原始的最后一个节区的节表头，
  //有个问题：因为检查节表属性是在PE的系统装载PE的时候，此时PE正准备加载到内存，系统根据PE节表头属性设置PE节区相关区域地址的内存属性，
  //此时PE结构已经装载进了内存，再还原原始节表头，想借此还原原始节区的节区属性，其实已经晚了。
  //但是还是复原一下吧。。。。
	DWORD NumberOfExeSection = pExeFileheader->NumberOfSections;
	PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileheader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pExeEndSectionheader = pExeFirstSectionHeader;
	for (int i = 1; i < NumberOfExeSection; i++) {
		pExeEndSectionheader++;
	}//定位到最后一个节表头
	SourceAddress = (DWORD)&pOldDataAndShellCodeStruct->EndSectionHeader;
	DestinationAddress = (DWORD)pExeEndSectionheader;
	CopySize = sizeof(pOldDataAndShellCodeStruct->EndSectionHeader);
	//同样的，写之前改内存页属性为可读可写
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, PAGE_READWRITE, &lpflOldProtect);
	
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
	//写之后复原。
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, lpflOldProtect, &lpflOldProtect);
	

//复原AddressOfEntryPoint
	//同样的，写之前改内存页属性为可读可写
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID)&(pExeOptionalHeader->AddressOfEntryPoint), 4 , PAGE_READWRITE, &lpflOldProtect);

	pExeOptionalHeader->AddressOfEntryPoint = pOldDataAndShellCodeStruct->AddressOfEntryPoint;
	
	//写之后复原。
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->AddressOfEntryPoint), 4, lpflOldProtect, &lpflOldProtect);

//复原ImageBase
		//同样的，写之前改内存页属性为可读可写
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->ImageBase), 4, PAGE_READWRITE, &lpflOldProtect);

	pExeOptionalHeader->ImageBase = pOldDataAndShellCodeStruct->ImageBase;

	//写之后复原。
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->ImageBase), 4, lpflOldProtect, &lpflOldProtect);
	
	BYTE Key = 0xCC;

//检查一下是否在被调试，设置反调试。
	if (*(pPeb + 2)) {
		Key = 0x33;
		return ;
	}

	//pMessageBoxW(0, 0, 0, 0);
//对原始加密的节区进行解密
  //*************** Decrypt Start ************************
	PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
	//pMessageBoxW(0, 0, 0, 0);
	if (pExeSectionHeader->PointerToRawData == 0)//防止第一个节区为.textbss
		pExeSectionHeader++;
	for (int i = 0; i < pExeFileheader->NumberOfSections; i++, pExeSectionHeader++) {
		//资源表所在节区没有加密，不需要解密

		if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
			//pMessageBoxW(0, 0, 0, 0);
			continue;
		}

		//SizeOfEncryptionSection
		PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->VirtualAddress);
		DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;
		//同样的，写之前改内存页属性为可读可写
		lpflOldProtect = 0;
		//这里节区属性一定要可读可写可执行，因为最后一个节区包含我们正在执行的代码，如果不能可执行的话，直接报错。
		pVirtualProtect((LPVOID) pStartAddrOfEncryption, SizeOfEncryptionSection, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
		for (int k = 0; k < SizeOfEncryptionSection; k++) {
			pStartAddrOfEncryption[k] ^= Key;
		}
		//写之后复原。
		pVirtualProtect((LPVOID)pStartAddrOfEncryption, SizeOfEncryptionSection, lpflOldProtect, &lpflOldProtect);
		
	}
  //*************** Decrypt End ************************

//修正重定位表
	//pMessageBoxW(0, 0, 0, 0);
	DWORD ImageOffset = pExeModule - pExeOptionalHeader->ImageBase;
	if ( ImageOffset ) {//代表需要重定位
		PIMAGE_BASE_RELOCATION pExeBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pExeModule + pExeDataDirectory[5].VirtualAddress);
		//pMessageBoxW(0, 0, 0, 0);
		while (pExeBaseRelocation->VirtualAddress) {
			PWORD pExeOffsetReloacation = (PWORD)((DWORD)pExeBaseRelocation + 8);
			//pMessageBoxW(0, 0, 0, 0);
			for (int i = 0; i < (pExeBaseRelocation->SizeOfBlock - 8) / 2; i++) {
				if ((*pExeOffsetReloacation >> 12) == 0x3) {//代表这个重定位地址偏移有效
					PDWORD pExeRelocation = (PDWORD)(pExeModule + pExeBaseRelocation->VirtualAddress + (*pExeOffsetReloacation & 0xfff));//这个地址里存储的是 需要重定位的地址
					//同样的，写之前改内存页属性为可读可写
					lpflOldProtect = 0;
					pVirtualProtect((LPVOID)(pExeRelocation), 4, PAGE_READWRITE, &lpflOldProtect);
					*pExeRelocation += ImageOffset;//进行重定位
					//写之后复原。
					pVirtualProtect((LPVOID)(pExeRelocation), 4, lpflOldProtect, &lpflOldProtect);
				}
				pExeOffsetReloacation++;
			}
			pExeBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pExeBaseRelocation + pExeBaseRelocation->SizeOfBlock);			
		}
	}


	
//修正IAT表
	PIMAGE_IMPORT_DESCRIPTOR pExeImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pExeModule + pExeDataDirectory[1].VirtualAddress);
	//pMessageBoxW(0, 0, 0, 0);
	if (pExeDataDirectory[1].VirtualAddress) {
		while (pExeImportDescriptor->Name) {
			HMODULE pDllModule = pLoadLibrary((LPCSTR)(pExeModule + pExeImportDescriptor->Name));
			PDWORD pExeINT = (PDWORD)(pExeModule + pExeImportDescriptor->OriginalFirstThunk);
			PDWORD pExeIAT = (PDWORD)(pExeModule + pExeImportDescriptor->FirstThunk);
			//pMessageBoxW(0, 0, 0, 0);
			for (int i = 0; *(pExeINT + i); i++) {
				//pMessageBoxW(0, 0, 0, 0);
				//同样的，写之前改内存页属性为可读可写
				lpflOldProtect = 0;
				pVirtualProtect((LPVOID) (pExeIAT + i), 4, PAGE_READWRITE, &lpflOldProtect);
				if ( (*(pExeINT + i) & 0x80000000) == 0x80000000) {
					//按函数序号导入。
					*(pExeIAT + i) = (DWORD)pGetProcAddress(pDllModule, (LPCSTR)(*(pExeINT + i) & 0x7fffffff));
				}
				else {//按函数名称导入
					PIMAGE_IMPORT_BY_NAME pExeImportByName = (PIMAGE_IMPORT_BY_NAME)(pExeModule + *(pExeINT + i));
					*(pExeIAT + i) = (DWORD)pGetProcAddress(pDllModule, pExeImportByName->Name);
				}
				//写之后复原。
				pVirtualProtect((LPVOID)(pExeIAT + i), 4, lpflOldProtect, &lpflOldProtect);

				//将INT置零
				//同样的，写之前改内存页属性为可读可写
				lpflOldProtect = 0;
				pVirtualProtect((LPVOID)(pExeINT + i), 4, PAGE_READWRITE, &lpflOldProtect);

				*(pExeINT + i) = 0;

				//写之后复原。
				pVirtualProtect((LPVOID)(pExeINT + i), 4, lpflOldProtect, &lpflOldProtect);
			}
			pExeImportDescriptor++;
		}
	}
	wchar_t szGood[] = { 0xca,0xf1,0xfc,0xf5,0xf5,0xb9,0xfa,0xf6,0xfd,0xfc,0xb9,0xfd,0xf6,0xf7,0xfc,0 };// { 'S','h','e','l','l',' ','c','o','d','e',' ','d','o','n','e',0 };
	for (int i = 0; szGood[i]; i++) {
		szGood[i] ^= 0x99;
	}
	pMessageBoxW(0, szGood, 0, 0);
	DWORD AddrOfEntryPoint = pExeModule + pExeOptionalHeader->AddressOfEntryPoint;
	_asm{
		mov eax, AddrOfEntryPoint
		call eax;
	}



}




void RemoteThreadInjectShellcode(DWORD ProcessId) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, ProcessId);
	if (!hProcess) {
		MessageBox(0, "OpenProcess", "Failed", 0);
		return;
	}
	DWORD SizeOfShellcode = (DWORD)RemoteThreadInjectShellcode - (DWORD)Pe_selfStarting_Shell;

	LPVOID pAddrOfProcessIdShellcode = VirtualAllocEx(hProcess, NULL, SizeOfShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pAddrOfProcessIdShellcode) {
		MessageBox(0, "VirtualAllocEx", "Failed", 0);
		return;
	}
	int flag = WriteProcessMemory(hProcess, pAddrOfProcessIdShellcode,(LPCVOID)Pe_selfStarting_Shell, SizeOfShellcode, NULL);
	if (!flag) {
		MessageBox(0, "WriteProcessMemory", "Failed", 0);
		return;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,(LPTHREAD_START_ROUTINE) pAddrOfProcessIdShellcode, NULL, 0, NULL);
	if (!hThread) {
		MessageBox(0, "CreateRemoteThread", "Failed", 0);
		return;
	}
	WaitForSingleObject(hThread, INFINITE);
	MessageBox(0, "RemoteThreadInjectShellcode", "Successfully!", 0);
	CloseHandle(hThread);
	CloseHandle(hProcess);
}

void Add_Pe_selfStarting_Shell(LPCSTR FileName) {


	HANDLE hFile = CreateFile((LPCSTR)FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(0, "CreateFile", "Failed!", 0);
		return;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);
	DWORD SizeOfShellcode = (DWORD)RemoteThreadInjectShellcode - (DWORD)Pe_selfStarting_Shell;

//分配内存，文件原始大小 + Shell代码大小 + 备份所有目录项大小 + 最后一个节表头大小 + 备份AddressOfEntryPoint的4字节（备份最后一个节表头）+ 备份ImageBase(因为系统加载PE会自动更改ImageBase)
	// sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) == 176字节，实际上其中最后一个成员ShellCode占的4字节，是额外申请的内存
	LPVOID pBuffer = VirtualAlloc(NULL, FileSize + SizeOfShellcode + sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) , MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		MessageBox(0, "VirtualAlloc", "Failed!", 0);
		return;
	}
	DWORD dwRead = 0;
	if (!ReadFile(hFile, pBuffer, FileSize, &dwRead, NULL)) {
		MessageBox(0, "ReadFile", "Failed!", 0);
		return;
	}
	CloseHandle(hFile);
	
//解析PE头，验证PE格式
	PIMAGE_DOS_HEADER pExeDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (pExeDosHeader->e_magic != 0x5A4D) {
		MessageBox(0, "Not PE File!! 0x5A4D->MZ", "Failed!", 0);
		return;
	}
	PIMAGE_NT_HEADERS32 pExeNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pExeDosHeader + pExeDosHeader->e_lfanew);
	if (pExeNtHeader->Signature != 0x00004550) {
		MessageBox(0, "Not PE File!! 0x00004550->PE", "Failed!", 0);
		return;
	}
	PIMAGE_FILE_HEADER pExeFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pExeNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pExeOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pExeFileHeader + IMAGE_SIZEOF_FILE_HEADER);
//验证是否时32位pe结构
	if (pExeOptionalHeader->Magic != 0x10B) {
		MessageBox(0, "Not 32bit PE!! OptionalHeader->Magic != 0x10B", "Failed!", 0);
		return;
	}

//然后把目录项8*16字节 和 最后一个节表头40字节 备份到文件结尾，相当于构造我制定的结构体
	PIMAGE_SECTION_HEADER pExeEndSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
	for (int i = 1; i < pExeFileHeader->NumberOfSections; i++) {
		pExeEndSectionHeader++;
	}//pExeEndSectionHeader 定位到最后一个节表头


	DWORD SourceAddress = 0;
	DWORD DestinationAddress = 0;
	DWORD CopySize = 0;

	//标志是否含有证书。
	DWORD SizeOfCertificateTable = FileSize - (pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData);
	LPCSTR pCertificateTable = NULL;
	if (SizeOfCertificateTable ) {
		//备份证书数据
		pCertificateTable = (LPCSTR)VirtualAlloc(NULL, SizeOfCertificateTable , MEM_COMMIT, PAGE_READWRITE);
		if (!pCertificateTable) {
			MessageBox(0, "VirtualAlloc pCertificateTable", "Failed!", 0);
			return;
		}
		SourceAddress = (DWORD)pBuffer+(FileSize-SizeOfCertificateTable);
		DestinationAddress = (DWORD)pCertificateTable;
		CopySize = SizeOfCertificateTable;
		_asm {
			mov esi, SourceAddress;
			mov edi, DestinationAddress;
			mov ecx, CopySize;
			rep movsb;
		}

	}
		

	//下面这样定位的方式，有一个缺陷，因为有些PE再最后一个节区的后面，还加上了一些数据（Certificate Table），这些数据不包含再最后一个节区后面，但是SizeOfImage却包含了.
	PMY_OLD_DATA_AND_SHELL_CODE_STRUCT pOldDataAndShellCodeStruct = (PMY_OLD_DATA_AND_SHELL_CODE_STRUCT)((DWORD)pBuffer + pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData);
	DWORD AddrOfEntryPoint = pOldDataAndShellCodeStruct->AddressOfEntryPoint;



	SourceAddress = (DWORD) & (pExeOptionalHeader->DataDirectory);
	DestinationAddress = (DWORD)pOldDataAndShellCodeStruct->DataDirectory; 
	CopySize = sizeof(pOldDataAndShellCodeStruct->DataDirectory);
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
//再将整个原始的目录项置零
	for (int i = 0; i < 16; i++) {
		pExeOptionalHeader->DataDirectory[i].VirtualAddress = 0;
		pExeOptionalHeader->DataDirectory[i].Size = 0;
	}
//复原资源表项的RVA，因为资源表所在节区不加密。
	pExeOptionalHeader->DataDirectory[2].VirtualAddress = pOldDataAndShellCodeStruct->DataDirectory[2].VirtualAddress;
	pExeOptionalHeader->DataDirectory[2].Size = pOldDataAndShellCodeStruct->DataDirectory[2].Size;

//把最后一个节区头40字节备份过去

	SourceAddress = (DWORD)pExeEndSectionHeader;
	DestinationAddress = (DWORD)&pOldDataAndShellCodeStruct->EndSectionHeader;
	CopySize = sizeof(pOldDataAndShellCodeStruct->EndSectionHeader);

	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}

//备份AddressOfEntryPoint的4字节
	pOldDataAndShellCodeStruct->AddressOfEntryPoint = pExeOptionalHeader->AddressOfEntryPoint;
//备份ImageBase
	pOldDataAndShellCodeStruct->ImageBase = pExeOptionalHeader->ImageBase;
//最后把Shell代码复制过去
	SourceAddress = (DWORD)Pe_selfStarting_Shell;
	DestinationAddress = (DWORD)&pOldDataAndShellCodeStruct->ShellCode; 
	CopySize = SizeOfShellcode;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}


//对所有原始节区进行加密
  //****************** Encrypt Start *********************	
	//再第一个节区头里找起始地址
	PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
	DWORD NumberOfSection = pExeFileHeader->NumberOfSections;

	PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
	if (pExeSectionHeader->PointerToRawData == 0)//防止第一个节区为.textbss
		pExeSectionHeader++;
	//遍历每个节区进行加密
	for ( ; pExeSectionHeader->VirtualAddress ; pExeSectionHeader++) {
		//不加密资源表所在节区
		if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
			continue;
		}
		PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->PointerToRawData);//加密节区的起始地址
		DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;//从起始地址开始加密的所有节区大小。
		for (int i = 0; i < SizeOfEncryptionSection; i++) {
			pStartAddrOfEncryption[i] ^= 0xCC;
		}
	}
  //****************** Encrypt End *********************

//修改PE文件格式，AddressOfEntryPoint指向ShellCode，最后一个节区的文件大小SizeOfRawData、内存大小Virtual Size，属性可读可写可执行， SizeOfImage增加后对齐FileAlignment， 
	
//8 * 16 代表目录项大小，40代表最后一个节区大小，4字节代表备份的AddressOfEntryPoint
	pExeOptionalHeader->AddressOfEntryPoint = pExeEndSectionHeader->VirtualAddress + pExeEndSectionHeader->SizeOfRawData + sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) - 4;//减4是因为我定义的结构体里最后一个成员已经是ShellCode，占4字节。

	DWORD EndSectionSize = (sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) - 4 + SizeOfShellcode) + (pExeOptionalHeader->SizeOfImage - pExeEndSectionHeader->VirtualAddress);
	if (EndSectionSize % pExeOptionalHeader->FileAlignment) {
		pExeEndSectionHeader->SizeOfRawData = (EndSectionSize /pExeOptionalHeader->FileAlignment +1)*pExeOptionalHeader->FileAlignment;
	}
	else {
		pExeEndSectionHeader->SizeOfRawData  = (EndSectionSize / pExeOptionalHeader->FileAlignment) * pExeOptionalHeader->FileAlignment;
	}
	pExeEndSectionHeader->Misc.VirtualSize = pExeEndSectionHeader->SizeOfRawData;

	pExeEndSectionHeader->Characteristics = (pExeEndSectionHeader->Characteristics) | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;

	pExeOptionalHeader->SizeOfImage = pExeEndSectionHeader->VirtualAddress + pExeEndSectionHeader->SizeOfRawData;







//构造新的文件名
	DWORD SizeOfFileName = 0;//记录文件地址的长度
	for (SizeOfFileName = 0; FileName[SizeOfFileName]; SizeOfFileName++) { ; }//计算FileName的长度
	LPCSTR pNewFileName = (LPCSTR)VirtualAlloc(NULL, SizeOfFileName + 20, MEM_COMMIT, PAGE_READWRITE);
	if (!pNewFileName) {
		MessageBox(0, "VirtualAlloc pNewFileName", "Failed!", 0);
		return;
	}
	SourceAddress = (DWORD)FileName;
	DestinationAddress = (DWORD)pNewFileName;
	CopySize = SizeOfFileName;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
	char NewFileEnd[] = { '.', 's', 'h', 'e', 'l', 'l', '.', 'e', 'x', 'e', 0 };
	SourceAddress = (DWORD)NewFileEnd;
	DestinationAddress = (DWORD)pNewFileName+ SizeOfFileName;
	CopySize = 11;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}


//最后写入新文件
	HANDLE hNewFile = CreateFile(pNewFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, "CreateFile NewFile", "Failed!", 0);
		return;
	}
	DWORD dwWrite=0;

	LPCSTR pNewBuffer = (LPCSTR)VirtualAlloc(NULL, pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData + SizeOfCertificateTable, MEM_COMMIT, PAGE_READWRITE);
	if (!pNewBuffer) {
		MessageBox(0, "VirtualAlloc pNewBuffer", "Failed!", 0);
		return;
	}
	SourceAddress = (DWORD)pBuffer;
	DestinationAddress = (DWORD)pNewBuffer;
	//CopySize = FileSize + SizeOfShellcode + sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT);
	CopySize = pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}

	//判断有无证书，有证书再把证书复制到文件结尾。然后修正目录项里的CertificateTable RVA，因为这些数据没有被加秘。
	if (SizeOfCertificateTable) {
		SourceAddress = (DWORD)pCertificateTable;
		DestinationAddress = (DWORD)pNewBuffer + pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData;
		CopySize = SizeOfCertificateTable;
		_asm {
			mov esi, SourceAddress;
			mov edi, DestinationAddress;
			mov ecx, CopySize;
			rep movsb;
		}
		if (!VirtualFree((LPVOID)pCertificateTable, 0, MEM_RELEASE)) {
			MessageBox(0, "VirtualFree pCertificateTable", "Failed!", 0);
			return;;
		}
		pExeDosHeader = (PIMAGE_DOS_HEADER)pNewBuffer;
		pExeNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pExeDosHeader + pExeDosHeader->e_lfanew);
		pExeOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pExeNtHeader + 4 + IMAGE_SIZEOF_FILE_HEADER);
		//pExeOptionalHeader->DataDirectory[4]记录CertificateTable
		pExeOptionalHeader->DataDirectory[4].VirtualAddress = pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData;//证书项里的VIrtualAddress一般是FOA
		pExeOptionalHeader->DataDirectory[4].Size = SizeOfCertificateTable;
	}

	if (!WriteFile(hNewFile, pNewBuffer, pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData + SizeOfCertificateTable, &dwWrite, NULL))
	{
		DWORD flag = GetLastError();
		MessageBox(0, "WriteFile", "Failed!", 0);
		
		return;
	}
	CloseHandle(hNewFile);
	if (!VirtualFree((LPVOID)pBuffer, 0, MEM_RELEASE)) {
		MessageBox(0, "VirtualFree pNewFileName", "Failed!", 0);
		return;;
	}
	if (!VirtualFree((LPVOID)pNewFileName, 0, MEM_RELEASE)) {
		MessageBox(0, "VirtualFree pNewFileName", "Failed!", 0);
		return;;
	}
	if (!VirtualFree((LPVOID)pNewBuffer, 0, MEM_RELEASE)) {
		MessageBox(0, "VirtualFree pNewFileName", "Failed!", 0);
		return;;
	}
	MessageBox(0, "Add_Pe_selfStarting_Shell", "Successfully!", 0);

}



void Take_Out_Of_Shell_Code(LPCSTR FileName) {
	HANDLE hFile = CreateFile((LPCSTR)FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(0, "CreateFile", "Failed!", 0);
		return;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);
	//分配内存
	LPVOID pBuffer = VirtualAlloc(NULL, FileSize , MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBuffer) {
		MessageBox(0, "VirtualAlloc", "Failed!", 0);
		return;
	}
	DWORD dwRead = 0;
	if (!ReadFile(hFile, pBuffer, FileSize, &dwRead, NULL)) {
		MessageBox(0, "ReadFile", "Failed!", 0);
		return;
	}
	CloseHandle(hFile);

	//解析PE头，验证PE格式
	PIMAGE_DOS_HEADER pExeDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (pExeDosHeader->e_magic != 0x5A4D) {
		MessageBox(0, "Not PE File!! 0x5A4D->MZ", "Failed!", 0);
		return;
	}
	PIMAGE_NT_HEADERS32 pExeNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pExeDosHeader + pExeDosHeader->e_lfanew);
	if (pExeNtHeader->Signature != 0x00004550) {
		MessageBox(0, "Not PE File!! 0x00004550->PE", "Failed!", 0);
		return;
	}
	PIMAGE_FILE_HEADER pExeFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pExeNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pExeOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pExeFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	//验证是否时32位pe结构
	if (pExeOptionalHeader->Magic != 0x10B) {
		MessageBox(0, "Not 32bit PE!! OptionalHeader->Magic != 0x10B", "Failed!", 0);
		return;
	}

//判断是否有壳，判断最后一个节区里是否备份了最后一个节表头数据，如果备份了，肯定有相同节表名称字符串。
	//先定位最后一个节区，
	DWORD NumberOfExeSection = pExeFileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pExeEndSectionheader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader+pExeFileHeader->SizeOfOptionalHeader);
	for (int i = 1; i < NumberOfExeSection; i++) {
		pExeEndSectionheader++;
	}//定位到最后一个节表头

	//定位入口点之前是否有自定义的MY_OLD_DATA_AND_SHELL_CODE_STRUCT结构体
	//先将OEP转换的FOA,如果有壳，那么一般在最后一个节区
	int Offset = pExeOptionalHeader->AddressOfEntryPoint - pExeEndSectionheader->VirtualAddress;
	if (Offset > 0 && Offset < pExeEndSectionheader->SizeOfRawData) {
		//此时可能有Pe_selfStarting_Shell，再进一步判断
		DWORD FoaOfOEP = pExeEndSectionheader->PointerToRawData + Offset;
		PMY_OLD_DATA_AND_SHELL_CODE_STRUCT pMyOldDataAndShellCodeStruct = (PMY_OLD_DATA_AND_SHELL_CODE_STRUCT)((DWORD)pExeDosHeader + FoaOfOEP - sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) + 4);
		if (!memcmp(pExeEndSectionheader->Name, pMyOldDataAndShellCodeStruct->EndSectionHeader.Name, 8)) {
			MessageBox(0, "Yes,have Pe_selfStarting_Shell!", 0, 0);
			//进行去壳
			
			//查看是否有证书
			DWORD FoaOfCertificateTable = pExeOptionalHeader->DataDirectory[4].VirtualAddress;
			DWORD SizeOfCertificateTable = pExeOptionalHeader->DataDirectory[4].Size;

			pExeOptionalHeader->AddressOfEntryPoint = pMyOldDataAndShellCodeStruct->AddressOfEntryPoint;
			memcpy(pExeOptionalHeader->DataDirectory, pMyOldDataAndShellCodeStruct->DataDirectory, 8 * 16);
			memcpy(pExeEndSectionheader, &(pMyOldDataAndShellCodeStruct->EndSectionHeader), 40);
			pExeOptionalHeader->ImageBase = pMyOldDataAndShellCodeStruct->ImageBase;
			DWORD NewFileSize = (DWORD)(pExeDosHeader)-(DWORD)pMyOldDataAndShellCodeStruct;
			
			FileSize = pExeEndSectionheader->PointerToRawData + pExeEndSectionheader->SizeOfRawData;
			
			//若有证书，移动到正确的位置。
			if (FoaOfCertificateTable) {
				memcpy((void*)((DWORD)pBuffer + pExeOptionalHeader->DataDirectory[4].VirtualAddress), (void*)((DWORD)pBuffer + FoaOfCertificateTable), SizeOfCertificateTable);
				FileSize = pExeOptionalHeader->DataDirectory[4].VirtualAddress + pExeOptionalHeader->DataDirectory[4].Size;
			}

			//对节区进行解密
			//*************** Decrypt Start ************************
			PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
			DWORD NumberOfSection = pExeFileHeader->NumberOfSections;

			PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
			if (pExeSectionHeader->PointerToRawData == 0)//防止第一个节区为.textbss
				pExeSectionHeader++;
			//遍历每个节区进行解密
			for (; pExeSectionHeader->VirtualAddress; pExeSectionHeader++) {
				//资源表所在节区未被加密
				if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
					continue;
				}
				PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->PointerToRawData);//加密节区的起始地址
				DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;//从起始地址开始加密的所有节区大小。
				for (int i = 0; i < SizeOfEncryptionSection; i++) {
					pStartAddrOfEncryption[i] ^= 0xCC;
				}
			}
			//*************** Decrypt End ************************	

			//最后，保存文件。
			DWORD SizeOfFileName = 0;//记录文件地址的长度
			for (SizeOfFileName = 0; FileName[SizeOfFileName]; SizeOfFileName++) { ; }//计算FileName的长度
			LPCSTR pNewFileName = (LPCSTR)VirtualAlloc(NULL, SizeOfFileName + 20, MEM_COMMIT, PAGE_READWRITE);
			if (!pNewFileName) {
				MessageBox(0, "VirtualAlloc pNewFileName", "Failed!", 0);
				return;
			}
			memcpy((void*)pNewFileName, FileName, SizeOfFileName);
			char NewName[] = { 'N','e','w','.','e','x','e' ,0};
			memcpy((void*)(pNewFileName+SizeOfFileName), NewName, 8);
			HANDLE hNewFile = CreateFile(pNewFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hNewFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "CreateFile NewFile", "Failed!", 0);
				return;
			}
			DWORD dwWrite = 0;
			if (!WriteFile(hNewFile, pBuffer,FileSize, &dwWrite, NULL))
			{
				DWORD flag = GetLastError();
				MessageBox(0, "WriteFile", "Failed!", 0);

				return;
			}
			CloseHandle(hNewFile);
			if (!VirtualFree((LPVOID)pBuffer, 0, MEM_RELEASE)) {
				MessageBox(0, "VirtualFree pNewFileName", "Failed!", 0);
				return;;
			}

			MessageBox(0, "TakeOutOfShellCode!", "Successfully!", 0);
			return;

		}
	}

	MessageBox(0, "No, Don't has Pe_selfStarting_Shell!", 0, 0);


}


void ErrorInput() {
	printf("\n********************************* Tips ******************************************\n");

	printf("if:  Add_Pe_selfStarting_Shell please input: [.exe] i [FileName] \n     for example: Pe_selfStarting_Shell.exe i D:/Application/Test.exe\n\n");
	printf("or:  Take_Out_Of_Shell_Code please input: [.exe] o [FileName] \n      for example: Pe_selfStarting_Shell.exe o D:/Application/Test.exe.shell.exe\n\n");
	printf("*********************************************************************************\n");
}
//char FileName[100] = "D:/TipZhzj/tools/PE/1111PEview.exe";
//char FileName[] = "D:/TipZhzj/tools/Cheat Engine/Cheat Engine 7.2/Cheat Engine.exe";
//char FileName[] = "C:/Users/TipZhzj/AppData/Local/youdao/dict/Application/YodaoDict.exe";
//char FileName[1000] = { 0 };
int main(int argc, char* argv[]) {
	//MessageBox(0, 0, 0, 0);

	//Pe_selfStarting_Shell();
	//char FileName[] = { 'D',':','/','T','i','p','Z','h','z','j','/','c','o','d','e','/','M','i','c','r','o','s','o','f','t',' ','V','i','s','u','a','l',' ','S','t','u','d','i','o','/','s','o','u','r','c','e','/','p','r','o','j','e','c','t','/','T','e','s','t','E','x','e','/','R','e','l','e','a','s','e','/','T','e','s','t','E','x','e','.','e','x','e',0 };
	//RemoteThreadInjectShellcode(58572);
	//char FileName[] = "D:/TipZhzj/code/Microsoft Visual Studio/source/project/TestExe/Release/EasyRe.exe";
	//char FileName[] = "D:/TipZhzj/code/Microsoft Visual Studio/source/project/TestExe/Release/TestExe.exe";
	//printf("Please input Exe Name ( Only 32 bit exe),for example: C:/Users/TipZhzj/AppData/Local/youdao/dict/Application/YodaoDict.exe  \n: ");
	//gets_s(FileName,1000);	
	//char FileName[1000] = "C:/Users/TipZhzj/AppData/Local/youdao/dict/Application/YodaoDict.exe.shell.exe";
	//Add_Pe_selfStarting_Shell((LPCSTR)FileName);

	if (argc == 1) {
		MessageBox(0, "Enter parameters on the command line", "Tips:", 0);
		return 0;
	}

	if (argc != 3) {
		ErrorInput();
		return 0;
	}
	if (argv[1][0] == 'i') {
		Add_Pe_selfStarting_Shell(argv[2]);
	}
	else if (argv[1][0] == 'o') {
		Take_Out_Of_Shell_Code(argv[2]);
	}
	else {
		ErrorInput();
	}
	
	//	TakeOutOfShellCode((LPCSTR)FileName);
	return 0;
}

//D:/TipZhzj/tools/Cheat Engine/Cheat Engine 7.2/Cheat Engine.exe
