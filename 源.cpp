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

//Ĭ��InLoadOrderModuleList˫�����еĵ�һ������һ����_LDR_DATA_TABEL_ENTRY�ṹ��ָ���ģ��Ϊexe����
void Pe_selfStarting_Shell() {
	
	unsigned long HashKernel32 = 0x330;//KERNEL32.DLL�ַ����ۼӹ�ϣ��ֵ
	wchar_t* pKernelName = 0;
	unsigned long pKernel32Module = 0;
	unsigned long pExeModule = 0;//Ĭ��InLoadOrderModuleList˫�����еĵ�һ������һ����_LDR_DATA_TABEL_ENTRY�ṹ��ָ���ģ��Ϊexe����
	unsigned char* pPeb = 0;
	//MessageBox(0, 0, 0, 0);
//����PEB�ṹ�е�LDR�ṹ���ҵ�KERNEL32.DLL���ڴ��еĻ�ַ
	_asm {
		pushad;
		mov eax, fs: [0x30] ;//fs�Ĵ�������TEB��ƫ��0x30ָ��PEB
		mov pPeb, eax;
		mov eax, [eax + 0xc];//ָ��_PEB_LDR_DATA

		mov ebx, eax;
		add ebx, 0xc;//�����InLoadOrderModuleList˫��������ʼλ�ã������ж��Ƿ�ѭ��������

		mov eax, [eax + 0xc];//����eaxָ��InLoadOrderModuleList˫�����еĵ�һ������һ����_LDR_DATA_TABEL_ENTRY�ṹ
	//**** start ********
		push eax;//��ʱ��eaxָ��ָ��InLoadOrderModuleList˫�����еĵ�һ������һ����_LDR_DATA_TABEL_ENTRY�ṹ
				 //�������Ϊ������һ������ΪList_Entry��һ��˫��������ʱ�ֱ�ָ����һ������һ��_LDR_DATA_TABEL_ENTRY�ṹ
				 //һ�㵹����һ�����ص�ģ��Ϊexe����
		mov eax, [eax + 0x18];//����һ���Լ�exeģ�����ڴ��еĻ�ַ
		mov pExeModule, eax;
		pop eax;
	//**** end ********
		//��ʼ����˫������ֱ���ҵ�Kenel32.dll
	Addr1:

		mov edi, [eax + 0x30];//ȡBaseDLLName��UNICODE_STRING���еĵ�5�ֽڣ�pBuffer��ָ��ģ����
		
		//******start �����ǽ���HASH�㷨����BaseDllName�е������ַ������ۼӣ��õ�hashֵ�����Ψһ������
		mov ecx, 12 * 2;//unicode�ַ��������Գ�2
		xor esi, esi;
	
	NextKernel32:
		xor ebx, ebx;
		add bl, byte ptr[edi + ecx - 1];
		add esi, ebx;
		loop NextKernel32;
		//�Ƚ����õ���hashֵ�������֤���ҵ�KERNEL32.DLL��ģ��	
		cmp esi, HashKernel32;
		je End;
		//******end

		mov eax, [eax];
		cmp eax, ebx;
		jne Addr1;
	End:
		mov eax, [eax + 0x18];//_LDR_DATA_TABLE_ENTRY��ƫ��0x18->DLLbase,ָ���ģ�����ַ����KERNEL32.dll
		mov pKernel32Module, eax;
		mov pKernelName, edi;
		nop;
		nop;
		popad;
	}

//����KERNEL32��pe�ṹ����ȡGetProcAddress������ַ��
	PIMAGE_DOS_HEADER pKernel32DosHeader = (PIMAGE_DOS_HEADER)pKernel32Module;
	PIMAGE_NT_HEADERS32 pKernel32NtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pKernel32DosHeader + pKernel32DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pKernel32FileHeader = (PIMAGE_FILE_HEADER)((DWORD)pKernel32NtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pKernel32OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pKernel32FileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_DATA_DIRECTORY pKernel32DataDirectory = (PIMAGE_DATA_DIRECTORY)pKernel32OptionalHeader->DataDirectory;
	PIMAGE_EXPORT_DIRECTORY pKernel32ModuleExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pKernel32Module+pKernel32DataDirectory[0].VirtualAddress);
	
	typedef FARPROC(WINAPI* PGETPROCADDRESS)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
	PGETPROCADDRESS pGetProcAddress = NULL;
	unsigned long HashGetProcAddress = 0x57A;//GetProcAddress�ַ����ۼӹ�ϣ��ֵ,Ascll�ַ�������14���ַ�
//�����������ҵ�GetProcAddress�������Ժ�����������Ascll�ַ���
	unsigned long* pAddressOfNames = (unsigned long*)(pKernel32Module + pKernel32ModuleExportDirectory->AddressOfNames);//�����������Ʊ����Ǵ洢����ָ�򵼳��������Ƶ�RVA
	DWORD Offset_Of_AddressOfNames = 0;//��¼GetProcAddress�����ں������Ʊ��е�ƫ�����


	while (pAddressOfNames) {

		char* pNameOfFunction = (char*)(pKernel32Module + *pAddressOfNames);
		//�Ժ������ɽ����Զ���hash���㣬�����ۼ���ֵ����i<14��ΪGetProcAddress��������Ϊ14���ַ�
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
	unsigned long Ordinal_Of_AddressOfFunctions = (unsigned long)*(pAddressOfNameOrdinals + Offset_Of_AddressOfNames);//�ں�����ű���ȡ�������
	unsigned long* pAddressOfFunctions = (unsigned long*)(pKernel32Module + pKernel32ModuleExportDirectory->AddressOfFunctions);
	pGetProcAddress = (PGETPROCADDRESS)(pKernel32Module + *(pAddressOfFunctions+Ordinal_Of_AddressOfFunctions));


//ͨ��pGetProcAddress��ȡLoadLibrary�����ĵ�ַ
	typedef HMODULE(WINAPI* PLOADLIBRARY)(_In_ LPCSTR lpLibFileName);
	char szLoadLibraryA[] = { 0xd5,0xf6,0xf8,0xfd,0xd5,0xf0,0xfb,0xeb,0xf8,0xeb,0xe0,0xd8,0 };//{ 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	for (int i = 0; szLoadLibraryA[i]; i++) {
		szLoadLibraryA[i] ^= 0x99;
	}
	PLOADLIBRARY pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)pKernel32Module, szLoadLibraryA);

	
//����USER32.dll,��ȡMessageBoxA������ַ
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
		mov eax, fs: [0x30] ;//fs�Ĵ�������TEB��ƫ��0x30ָ��PEB
		mov eax, [eax + 0xc];//ָ��_PEB_LDR_DATA

		mov ebx, eax;
		add ebx, 0xc;//�����InLoadOrderModuleList˫��������ʼλ�ã������ж��Ƿ�ѭ��������

		mov eax, [eax + 0xc];//����eaxָ��InLoadOrderModuleList˫�����еĵ�һ��_LDR_DATA_TABEL_ENTRY�ṹ

		//��ʼ����˫������ֱ���ҵ�Kenel32.dll
	Addr2:

		mov edi, [eax + 0x30];//ȡBaseDLLName��UNICODE_STRING���еĵ�5�ֽڣ�pBuffer��ָ��ģ����

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
	
//����PE�ṹ pExeModule
	PIMAGE_DOS_HEADER pExeDosHeader = (PIMAGE_DOS_HEADER)pExeModule;
	PIMAGE_NT_HEADERS32 pExeNtHeader = (PIMAGE_NT_HEADERS32)(pExeModule + pExeDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pExeFileheader = (PIMAGE_FILE_HEADER)((DWORD)pExeNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pExeOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pExeFileheader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_DATA_DIRECTORY pExeDataDirectory = (PIMAGE_DATA_DIRECTORY)(pExeOptionalHeader->DataDirectory);
	
//�ӱ��ݵ���������ȡԭʼĿ¼����и�ԭ
	//��ԭ��ʱ���漰�ڴ�д������Ҫ�ı��ڴ�ҳ���ԣ����С��Χ�ģ�����֮��ԭ
	typedef BOOL(WINAPI* PVIRTUALPROTECT)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
	char szVirtualProtect[] = { 0xcf,0xf0,0xeb,0xed,0xec,0xf8,0xf5,0xc9,0xeb,0xf6,0xed,0xfc,0xfa,0xed,0 }; //{ 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
	for (int i = 0; szVirtualProtect[i]; i++) {
		szVirtualProtect[i] ^= 0x99;
	}
	PVIRTUALPROTECT pVirtualProtect = (PVIRTUALPROTECT)pGetProcAddress((HMODULE)pKernel32Module, szVirtualProtect);

	//��λ��ǽṹ��λ��,+4��ӦΪsizeof(MyOldDataAndShellCodeStruct)���������һ����ԱShellCode��4�ֽڡ�
	PMY_OLD_DATA_AND_SHELL_CODE_STRUCT pOldDataAndShellCodeStruct = (PMY_OLD_DATA_AND_SHELL_CODE_STRUCT)(pExeModule + pExeOptionalHeader->AddressOfEntryPoint - sizeof(MyOldDataAndShellCodeStruct) + 4);
	
	DWORD SourceAddress = 0;
	DWORD DestinationAddress = 0;
	DWORD CopySize = 0;

	SourceAddress = (DWORD)pOldDataAndShellCodeStruct->DataDirectory;
	DestinationAddress = (DWORD)pExeOptionalHeader->DataDirectory;
	CopySize = sizeof(pOldDataAndShellCodeStruct->DataDirectory);
	//д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
	DWORD lpflOldProtect = 0;
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, PAGE_READWRITE, &lpflOldProtect);
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
	//д֮��ԭ��
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, lpflOldProtect, &lpflOldProtect);

	
//��ԭԭʼ�����һ�������Ľڱ�ͷ��
  //�и����⣺��Ϊ���ڱ���������PE��ϵͳװ��PE��ʱ�򣬴�ʱPE��׼�����ص��ڴ棬ϵͳ����PE�ڱ�ͷ��������PE������������ַ���ڴ����ԣ�
  //��ʱPE�ṹ�Ѿ�װ�ؽ����ڴ棬�ٻ�ԭԭʼ�ڱ�ͷ�����˻�ԭԭʼ�����Ľ������ԣ���ʵ�Ѿ����ˡ�
  //���ǻ��Ǹ�ԭһ�°ɡ�������
	DWORD NumberOfExeSection = pExeFileheader->NumberOfSections;
	PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileheader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pExeEndSectionheader = pExeFirstSectionHeader;
	for (int i = 1; i < NumberOfExeSection; i++) {
		pExeEndSectionheader++;
	}//��λ�����һ���ڱ�ͷ
	SourceAddress = (DWORD)&pOldDataAndShellCodeStruct->EndSectionHeader;
	DestinationAddress = (DWORD)pExeEndSectionheader;
	CopySize = sizeof(pOldDataAndShellCodeStruct->EndSectionHeader);
	//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, PAGE_READWRITE, &lpflOldProtect);
	
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}
	//д֮��ԭ��
	pVirtualProtect((LPVOID)DestinationAddress, CopySize, lpflOldProtect, &lpflOldProtect);
	

//��ԭAddressOfEntryPoint
	//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID)&(pExeOptionalHeader->AddressOfEntryPoint), 4 , PAGE_READWRITE, &lpflOldProtect);

	pExeOptionalHeader->AddressOfEntryPoint = pOldDataAndShellCodeStruct->AddressOfEntryPoint;
	
	//д֮��ԭ��
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->AddressOfEntryPoint), 4, lpflOldProtect, &lpflOldProtect);

//��ԭImageBase
		//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
	lpflOldProtect = 0;
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->ImageBase), 4, PAGE_READWRITE, &lpflOldProtect);

	pExeOptionalHeader->ImageBase = pOldDataAndShellCodeStruct->ImageBase;

	//д֮��ԭ��
	pVirtualProtect((LPVOID) & (pExeOptionalHeader->ImageBase), 4, lpflOldProtect, &lpflOldProtect);
	
	BYTE Key = 0xCC;

//���һ���Ƿ��ڱ����ԣ����÷����ԡ�
	if (*(pPeb + 2)) {
		Key = 0x33;
		return ;
	}

	//pMessageBoxW(0, 0, 0, 0);
//��ԭʼ���ܵĽ������н���
  //*************** Decrypt Start ************************
	PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
	//pMessageBoxW(0, 0, 0, 0);
	if (pExeSectionHeader->PointerToRawData == 0)//��ֹ��һ������Ϊ.textbss
		pExeSectionHeader++;
	for (int i = 0; i < pExeFileheader->NumberOfSections; i++, pExeSectionHeader++) {
		//��Դ�����ڽ���û�м��ܣ�����Ҫ����

		if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
			//pMessageBoxW(0, 0, 0, 0);
			continue;
		}

		//SizeOfEncryptionSection
		PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->VirtualAddress);
		DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;
		//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
		lpflOldProtect = 0;
		//�����������һ��Ҫ�ɶ���д��ִ�У���Ϊ���һ������������������ִ�еĴ��룬������ܿ�ִ�еĻ���ֱ�ӱ���
		pVirtualProtect((LPVOID) pStartAddrOfEncryption, SizeOfEncryptionSection, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
		for (int k = 0; k < SizeOfEncryptionSection; k++) {
			pStartAddrOfEncryption[k] ^= Key;
		}
		//д֮��ԭ��
		pVirtualProtect((LPVOID)pStartAddrOfEncryption, SizeOfEncryptionSection, lpflOldProtect, &lpflOldProtect);
		
	}
  //*************** Decrypt End ************************

//�����ض�λ��
	//pMessageBoxW(0, 0, 0, 0);
	DWORD ImageOffset = pExeModule - pExeOptionalHeader->ImageBase;
	if ( ImageOffset ) {//������Ҫ�ض�λ
		PIMAGE_BASE_RELOCATION pExeBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pExeModule + pExeDataDirectory[5].VirtualAddress);
		//pMessageBoxW(0, 0, 0, 0);
		while (pExeBaseRelocation->VirtualAddress) {
			PWORD pExeOffsetReloacation = (PWORD)((DWORD)pExeBaseRelocation + 8);
			//pMessageBoxW(0, 0, 0, 0);
			for (int i = 0; i < (pExeBaseRelocation->SizeOfBlock - 8) / 2; i++) {
				if ((*pExeOffsetReloacation >> 12) == 0x3) {//��������ض�λ��ַƫ����Ч
					PDWORD pExeRelocation = (PDWORD)(pExeModule + pExeBaseRelocation->VirtualAddress + (*pExeOffsetReloacation & 0xfff));//�����ַ��洢���� ��Ҫ�ض�λ�ĵ�ַ
					//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
					lpflOldProtect = 0;
					pVirtualProtect((LPVOID)(pExeRelocation), 4, PAGE_READWRITE, &lpflOldProtect);
					*pExeRelocation += ImageOffset;//�����ض�λ
					//д֮��ԭ��
					pVirtualProtect((LPVOID)(pExeRelocation), 4, lpflOldProtect, &lpflOldProtect);
				}
				pExeOffsetReloacation++;
			}
			pExeBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pExeBaseRelocation + pExeBaseRelocation->SizeOfBlock);			
		}
	}


	
//����IAT��
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
				//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
				lpflOldProtect = 0;
				pVirtualProtect((LPVOID) (pExeIAT + i), 4, PAGE_READWRITE, &lpflOldProtect);
				if ( (*(pExeINT + i) & 0x80000000) == 0x80000000) {
					//��������ŵ��롣
					*(pExeIAT + i) = (DWORD)pGetProcAddress(pDllModule, (LPCSTR)(*(pExeINT + i) & 0x7fffffff));
				}
				else {//���������Ƶ���
					PIMAGE_IMPORT_BY_NAME pExeImportByName = (PIMAGE_IMPORT_BY_NAME)(pExeModule + *(pExeINT + i));
					*(pExeIAT + i) = (DWORD)pGetProcAddress(pDllModule, pExeImportByName->Name);
				}
				//д֮��ԭ��
				pVirtualProtect((LPVOID)(pExeIAT + i), 4, lpflOldProtect, &lpflOldProtect);

				//��INT����
				//ͬ���ģ�д֮ǰ���ڴ�ҳ����Ϊ�ɶ���д
				lpflOldProtect = 0;
				pVirtualProtect((LPVOID)(pExeINT + i), 4, PAGE_READWRITE, &lpflOldProtect);

				*(pExeINT + i) = 0;

				//д֮��ԭ��
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

//�����ڴ棬�ļ�ԭʼ��С + Shell�����С + ��������Ŀ¼���С + ���һ���ڱ�ͷ��С + ����AddressOfEntryPoint��4�ֽڣ��������һ���ڱ�ͷ��+ ����ImageBase(��Ϊϵͳ����PE���Զ�����ImageBase)
	// sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) == 176�ֽڣ�ʵ�����������һ����ԱShellCodeռ��4�ֽڣ��Ƕ���������ڴ�
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
	
//����PEͷ����֤PE��ʽ
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
//��֤�Ƿ�ʱ32λpe�ṹ
	if (pExeOptionalHeader->Magic != 0x10B) {
		MessageBox(0, "Not 32bit PE!! OptionalHeader->Magic != 0x10B", "Failed!", 0);
		return;
	}

//Ȼ���Ŀ¼��8*16�ֽ� �� ���һ���ڱ�ͷ40�ֽ� ���ݵ��ļ���β���൱�ڹ������ƶ��Ľṹ��
	PIMAGE_SECTION_HEADER pExeEndSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
	for (int i = 1; i < pExeFileHeader->NumberOfSections; i++) {
		pExeEndSectionHeader++;
	}//pExeEndSectionHeader ��λ�����һ���ڱ�ͷ


	DWORD SourceAddress = 0;
	DWORD DestinationAddress = 0;
	DWORD CopySize = 0;

	//��־�Ƿ���֤�顣
	DWORD SizeOfCertificateTable = FileSize - (pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData);
	LPCSTR pCertificateTable = NULL;
	if (SizeOfCertificateTable ) {
		//����֤������
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
		

	//����������λ�ķ�ʽ����һ��ȱ�ݣ���Ϊ��ЩPE�����һ�������ĺ��棬��������һЩ���ݣ�Certificate Table������Щ���ݲ����������һ���������棬����SizeOfImageȴ������.
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
//�ٽ�����ԭʼ��Ŀ¼������
	for (int i = 0; i < 16; i++) {
		pExeOptionalHeader->DataDirectory[i].VirtualAddress = 0;
		pExeOptionalHeader->DataDirectory[i].Size = 0;
	}
//��ԭ��Դ�����RVA����Ϊ��Դ�����ڽ��������ܡ�
	pExeOptionalHeader->DataDirectory[2].VirtualAddress = pOldDataAndShellCodeStruct->DataDirectory[2].VirtualAddress;
	pExeOptionalHeader->DataDirectory[2].Size = pOldDataAndShellCodeStruct->DataDirectory[2].Size;

//�����һ������ͷ40�ֽڱ��ݹ�ȥ

	SourceAddress = (DWORD)pExeEndSectionHeader;
	DestinationAddress = (DWORD)&pOldDataAndShellCodeStruct->EndSectionHeader;
	CopySize = sizeof(pOldDataAndShellCodeStruct->EndSectionHeader);

	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}

//����AddressOfEntryPoint��4�ֽ�
	pOldDataAndShellCodeStruct->AddressOfEntryPoint = pExeOptionalHeader->AddressOfEntryPoint;
//����ImageBase
	pOldDataAndShellCodeStruct->ImageBase = pExeOptionalHeader->ImageBase;
//����Shell���븴�ƹ�ȥ
	SourceAddress = (DWORD)Pe_selfStarting_Shell;
	DestinationAddress = (DWORD)&pOldDataAndShellCodeStruct->ShellCode; 
	CopySize = SizeOfShellcode;
	_asm {
		mov esi, SourceAddress;
		mov edi, DestinationAddress;
		mov ecx, CopySize;
		rep movsb;
	}


//������ԭʼ�������м���
  //****************** Encrypt Start *********************	
	//�ٵ�һ������ͷ������ʼ��ַ
	PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
	DWORD NumberOfSection = pExeFileHeader->NumberOfSections;

	PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
	if (pExeSectionHeader->PointerToRawData == 0)//��ֹ��һ������Ϊ.textbss
		pExeSectionHeader++;
	//����ÿ���������м���
	for ( ; pExeSectionHeader->VirtualAddress ; pExeSectionHeader++) {
		//��������Դ�����ڽ���
		if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
			continue;
		}
		PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->PointerToRawData);//���ܽ�������ʼ��ַ
		DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;//����ʼ��ַ��ʼ���ܵ����н�����С��
		for (int i = 0; i < SizeOfEncryptionSection; i++) {
			pStartAddrOfEncryption[i] ^= 0xCC;
		}
	}
  //****************** Encrypt End *********************

//�޸�PE�ļ���ʽ��AddressOfEntryPointָ��ShellCode�����һ���������ļ���СSizeOfRawData���ڴ��СVirtual Size�����Կɶ���д��ִ�У� SizeOfImage���Ӻ����FileAlignment�� 
	
//8 * 16 ����Ŀ¼���С��40�������һ��������С��4�ֽڴ����ݵ�AddressOfEntryPoint
	pExeOptionalHeader->AddressOfEntryPoint = pExeEndSectionHeader->VirtualAddress + pExeEndSectionHeader->SizeOfRawData + sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) - 4;//��4����Ϊ�Ҷ���Ľṹ�������һ����Ա�Ѿ���ShellCode��ռ4�ֽڡ�

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







//�����µ��ļ���
	DWORD SizeOfFileName = 0;//��¼�ļ���ַ�ĳ���
	for (SizeOfFileName = 0; FileName[SizeOfFileName]; SizeOfFileName++) { ; }//����FileName�ĳ���
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


//���д�����ļ�
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

	//�ж�����֤�飬��֤���ٰ�֤�鸴�Ƶ��ļ���β��Ȼ������Ŀ¼�����CertificateTable RVA����Ϊ��Щ����û�б����ء�
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
		//pExeOptionalHeader->DataDirectory[4]��¼CertificateTable
		pExeOptionalHeader->DataDirectory[4].VirtualAddress = pExeEndSectionHeader->PointerToRawData + pExeEndSectionHeader->SizeOfRawData;//֤�������VIrtualAddressһ����FOA
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
	//�����ڴ�
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

	//����PEͷ����֤PE��ʽ
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
	//��֤�Ƿ�ʱ32λpe�ṹ
	if (pExeOptionalHeader->Magic != 0x10B) {
		MessageBox(0, "Not 32bit PE!! OptionalHeader->Magic != 0x10B", "Failed!", 0);
		return;
	}

//�ж��Ƿ��пǣ��ж����һ���������Ƿ񱸷������һ���ڱ�ͷ���ݣ���������ˣ��϶�����ͬ�ڱ������ַ�����
	//�ȶ�λ���һ��������
	DWORD NumberOfExeSection = pExeFileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pExeEndSectionheader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader+pExeFileHeader->SizeOfOptionalHeader);
	for (int i = 1; i < NumberOfExeSection; i++) {
		pExeEndSectionheader++;
	}//��λ�����һ���ڱ�ͷ

	//��λ��ڵ�֮ǰ�Ƿ����Զ����MY_OLD_DATA_AND_SHELL_CODE_STRUCT�ṹ��
	//�Ƚ�OEPת����FOA,����пǣ���ôһ�������һ������
	int Offset = pExeOptionalHeader->AddressOfEntryPoint - pExeEndSectionheader->VirtualAddress;
	if (Offset > 0 && Offset < pExeEndSectionheader->SizeOfRawData) {
		//��ʱ������Pe_selfStarting_Shell���ٽ�һ���ж�
		DWORD FoaOfOEP = pExeEndSectionheader->PointerToRawData + Offset;
		PMY_OLD_DATA_AND_SHELL_CODE_STRUCT pMyOldDataAndShellCodeStruct = (PMY_OLD_DATA_AND_SHELL_CODE_STRUCT)((DWORD)pExeDosHeader + FoaOfOEP - sizeof(MY_OLD_DATA_AND_SHELL_CODE_STRUCT) + 4);
		if (!memcmp(pExeEndSectionheader->Name, pMyOldDataAndShellCodeStruct->EndSectionHeader.Name, 8)) {
			MessageBox(0, "Yes,have Pe_selfStarting_Shell!", 0, 0);
			//����ȥ��
			
			//�鿴�Ƿ���֤��
			DWORD FoaOfCertificateTable = pExeOptionalHeader->DataDirectory[4].VirtualAddress;
			DWORD SizeOfCertificateTable = pExeOptionalHeader->DataDirectory[4].Size;

			pExeOptionalHeader->AddressOfEntryPoint = pMyOldDataAndShellCodeStruct->AddressOfEntryPoint;
			memcpy(pExeOptionalHeader->DataDirectory, pMyOldDataAndShellCodeStruct->DataDirectory, 8 * 16);
			memcpy(pExeEndSectionheader, &(pMyOldDataAndShellCodeStruct->EndSectionHeader), 40);
			pExeOptionalHeader->ImageBase = pMyOldDataAndShellCodeStruct->ImageBase;
			DWORD NewFileSize = (DWORD)(pExeDosHeader)-(DWORD)pMyOldDataAndShellCodeStruct;
			
			FileSize = pExeEndSectionheader->PointerToRawData + pExeEndSectionheader->SizeOfRawData;
			
			//����֤�飬�ƶ�����ȷ��λ�á�
			if (FoaOfCertificateTable) {
				memcpy((void*)((DWORD)pBuffer + pExeOptionalHeader->DataDirectory[4].VirtualAddress), (void*)((DWORD)pBuffer + FoaOfCertificateTable), SizeOfCertificateTable);
				FileSize = pExeOptionalHeader->DataDirectory[4].VirtualAddress + pExeOptionalHeader->DataDirectory[4].Size;
			}

			//�Խ������н���
			//*************** Decrypt Start ************************
			PIMAGE_SECTION_HEADER pExeFirstSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pExeOptionalHeader + pExeFileHeader->SizeOfOptionalHeader);
			DWORD NumberOfSection = pExeFileHeader->NumberOfSections;

			PIMAGE_SECTION_HEADER pExeSectionHeader = pExeFirstSectionHeader;
			if (pExeSectionHeader->PointerToRawData == 0)//��ֹ��һ������Ϊ.textbss
				pExeSectionHeader++;
			//����ÿ���������н���
			for (; pExeSectionHeader->VirtualAddress; pExeSectionHeader++) {
				//��Դ�����ڽ���δ������
				if (pExeOptionalHeader->DataDirectory[2].VirtualAddress >= pExeSectionHeader->VirtualAddress && pExeOptionalHeader->DataDirectory[2].VirtualAddress <= pExeSectionHeader->VirtualAddress + pExeSectionHeader->SizeOfRawData) {
					continue;
				}
				PBYTE pStartAddrOfEncryption = (PBYTE)((DWORD)pExeDosHeader + pExeSectionHeader->PointerToRawData);//���ܽ�������ʼ��ַ
				DWORD SizeOfEncryptionSection = pExeSectionHeader->SizeOfRawData;//����ʼ��ַ��ʼ���ܵ����н�����С��
				for (int i = 0; i < SizeOfEncryptionSection; i++) {
					pStartAddrOfEncryption[i] ^= 0xCC;
				}
			}
			//*************** Decrypt End ************************	

			//��󣬱����ļ���
			DWORD SizeOfFileName = 0;//��¼�ļ���ַ�ĳ���
			for (SizeOfFileName = 0; FileName[SizeOfFileName]; SizeOfFileName++) { ; }//����FileName�ĳ���
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
