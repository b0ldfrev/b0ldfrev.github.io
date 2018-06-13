---
layout:     post
title:      "Windows下通用ShellCode原理"
subtitle:   "基于GetProcAddress的ShellCode编写"
date:       2017-05-28 12:00:00
catalog: true
tags:
    - Windwos
    - ShellCode
    - PE
    - 病毒分析
 
---


>用 C 汇编实现，编译环境vc6.0, 实测 Win all x32 x64 系统可行

##  0x00 原理简述

* 利用fs寄存器，找到TEB的地址->PEB的地址。PEB的0xC偏移处为一个指向PEB\_LDR\_DATA结构体的指针Ldr，PEB\_LDR\_DATA的0xC的偏移处为一个指向LIST\_ENTRY结构体的指针InLoadOrderModuleList，这是一个按加载顺序构成的双向模块链表。同时LIST\_ENTRY的父结构体为LDR\_DATA\_TABLE\_ENTRY，该结构体里有俩有用信息->0x18  DLLBase(模块基址), ->0x2c  BaseDllName(指向UNICODE_STRING结构体 模块名字为unicode类型）   
* 利用上述InLoadOrderModuleList双向链表查找kernel32.dll加载到内存的位置，找到其导出表，定位kernel32.dll导出的GetProcAddress函数，使用GetProcAddress函数获取LoadLibrary的函数地址，使用LoadLibrary函数加载user32.dll动态链接库，获取user32.dll中MessageBox的函数地址,调用MessageBox函数。

##  0x01 代码实现

1, 分别为GetProcAddress，MessageBox(演示)，Loadlibrary 定义函数指针

	typedef DWORD (WINAPI *PGETPROCADDRESS) (HMODULE hModule , LPCSTR lpProcName);
	typedef int (WINAPI * PMESSAGEBOX) (HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType);
	typedef HMODULE (WINAPI * PLOADLIBRARY) (LPCTSTR lpFileName);

2, 定义UNICODE\_STRING ， PEB\_LDR_DATA ，LDR\_DATA\_TABLE\_ENTRY结构体

	typedef struct UNICODE_STRING
	{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
	}UNICODE_STRING;
	
	typedef struct PEB_LDR_DATA{
	DWORD Length;
	BYTE initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	VOID * EntryInProgress;
	}PEB_LDR_DATA;
	
	typedef struct LDR_DATA_TABLE_ENTRY
	{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	void* DllBase;
	void* EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	HANDLE SectionHandle;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	}LDR_DATA_TABLE_ENTRY;

3, 你在C/C++代码中定义一个全局变量，一个取值为“Hello world”的字符串，或直接把该字符串作为参数传递给某个函数。但是，编译器会把字符串放置在一个特定的Section中（如.rdata或.data）。所以定义模块和函数名的字符串的时候，为了使变量存在与栈中，因使用位置无关代码

	char szKernel32[]={'k',0,'e',0,'r',0,'n',0,'e',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,0,0};
	char szUser32[]={'U','S','E','R','3','2','.','d','l','l',0};
	char szGetProcAddr[]={'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
	char szLoadLibrary[]={'L','o','a','d','L','i','b','r','a','r','y','A',0};
	char szMessageBox[]={'M','e','s','s','a','g','e','B','o','x','A',0};

注意Dll模块名称为Unicode格式。

4, 内联汇编，找到指向InLoadOrderModuleList头的指针pBeg，pPLD指向下一个模块。

	__asm{
			mov eax,fs:[0x30]
			mov eax,[eax+0x0c]
			add eax,0x0c
			mov pBeg,eax
			mov eax,[eax]
			mov pPLD,eax 
	}

5, 遍历双向链表，找到kernel32.dll。由于有些系统中的kernel32.dll大小写不一样，所以这里在遍历时考虑大小写不同的情况。

	while(pPLD!=pBeg)
	{
	pLast=(WORD*)pPLD->BaseDllName.Buffer;
	pFirst=(WORD*)szKernel32;
	while(*pFirst && (*pFirst-32==*pLast||*pFirst==*pLast))
	{	pFirst++,pLast++;}
	if(*pFirst==*pLast)
	{
	dwKernelBase=(DWORD)pPLD->DllBase;
	break;
	}
	pPLD=(LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderModuleList.Flink;
	}

6, PE操作，遍历kernel32.dll的导出表，根据找到GetProcAddr函数地址。（AddressOfNames的偏移号 对应AddressOfNameOrdinals的偏移，找到的序号为AddressOfFunctions表的偏移）

	IMAGE_DOS_HEADER *pIDH=(IMAGE_DOS_HEADER *)dwKernelBase; 
	IMAGE_NT_HEADERS *pINGS=(IMAGE_NT_HEADERS *)((DWORD)dwKernelBase+pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY *pIED=(IMAGE_EXPORT_DIRECTORY*)((DWORD)dwKernelBase+pINGS
	->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	DWORD *pAddOfFun_Raw=(DWORD*)((DWORD)dwKernelBase+pIED->AddressOfFunctions);
	WORD *pAddOfOrd_Raw=(WORD*)((DWORD)dwKernelBase+pIED->AddressOfNameOrdinals);
	DWORD *pAddOfNames_Raw=(DWORD*)((DWORD)dwKernelBase+pIED->AddressOfNames);
	DWORD dwCnt=0;
	
	char *pFinded=NULL,*pSrc=szGetProcAddr;
	for(;dwCnt<pIED->NumberOfNames;dwCnt++)
	{
	pFinded=(char *)((DWORD)dwKernelBase+pAddOfNames_Raw[dwCnt]);
	while(*pFinded &&*pFinded==*pSrc) 
	{pFinded++;pSrc++;}
	if(*pFinded == *pSrc)
	{
	pGetProcAddress=(PGETPROCADDRESS)((DWORD)dwKernelBase+pAddOfFun_Raw[pAddOfOrd_Raw[dwCnt]]);
	break;
	}
	pSrc=szGetProcAddr;
	}

7, 现在有了GetProcAddr的函数地址，我们可以用LoadLibrary获得任何api的函数地址，并调用。

	pLoadLibrary=(PLOADLIBRARY)pGetProcAddress((HMODULE)dwKernelBase,szLoadLibrary);
	pMessageBox=(PMESSAGEBOX)pGetProcAddress(pLoadLibrary(szUser32),szMessageBox);
	char szTitle[]={'S','h','e','l','l','C','o','d','e',0};
	char szContent[]={0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,0x72,0x6c,0x64,0x20,0x21,0};
	pMessageBox(NULL,szContent,szTitle,0);

## 0x02 运行结果
这里Hello World弹窗仅供测试，要实现更多的功能的话还需要你自己去挖掘噢 ![0][pic2]


  ![0][pic1]


## 0x03 总结感悟

接下来研究的内容：

* Hash API
* 编码方式
* 简单免杀



























































[pic1]:data:image/png;base64,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

[pic2]:data:image/png;base64,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