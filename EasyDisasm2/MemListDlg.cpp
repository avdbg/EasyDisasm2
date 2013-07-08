#include "StdAfx.h"
#include "MemListDlg.h"

HANDLE hProcess = NULL;

LRESULT CMemListDlg::OnNMRclickListmemory(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/)
{
	return 0;
}

//已废弃
BOOL CMemListDlg::RefreshMemory()
{
	m_ListMemory.DeleteAllItems();

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,m_nPid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,m_nPid);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	MODULEENTRY32	me = {0};
	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hSnap,&me))
	{
		return FALSE;
	}

	std::vector<MODULEINFO>	vecModule;
	do 
	{
		MODULEINFO	ModuleInfo = {0};
		ModuleInfo.modBaseAddr = me.modBaseAddr;
		ModuleInfo.modBaseSize = me.modBaseSize;
		strcpy(ModuleInfo.szModule,me.szModule);

		//读取dos头
		IMAGE_DOS_HEADER dosHeader;
		SIZE_T	nRead;	
		if (!ReadProcessMemory(hProcess,me.modBaseAddr,&dosHeader,sizeof(IMAGE_DOS_HEADER),&nRead) 
			|| nRead != sizeof(IMAGE_DOS_HEADER)
			|| dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}

		//读取PE文件头
		IMAGE_NT_HEADERS ntHeader;
		if (!ReadProcessMemory(hProcess,me.modBaseAddr+dosHeader.e_lfanew,&ntHeader,sizeof(IMAGE_NT_HEADERS),&nRead) 
			|| nRead != sizeof(IMAGE_NT_HEADERS)
			|| ntHeader.Signature != IMAGE_NT_SIGNATURE)
		{
			return false;
		}
		//判断区段数量是否正确
		if (ntHeader.FileHeader.NumberOfSections<0
			|| ntHeader.FileHeader.NumberOfSections>96)
		{
			return false;
		}
		ModuleInfo.nNumSections = ntHeader.FileHeader.NumberOfSections;

		//从模块开始到区段表结束之前的大小
		ModuleInfo.nPEHeaderSize = dosHeader.e_lfanew 
			+ sizeof(IMAGE_NT_HEADERS) 
			+ sizeof(IMAGE_SECTION_HEADER)*ModuleInfo.nNumSections;

		//读取所有的区段头
		IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[ntHeader.FileHeader.NumberOfSections];
		if (!ReadProcessMemory(hProcess,me.modBaseAddr+dosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS),sectionHeaders,sizeof(IMAGE_SECTION_HEADER)*ntHeader.FileHeader.NumberOfSections,&nRead)
			|| nRead != sizeof(IMAGE_SECTION_HEADER)*ntHeader.FileHeader.NumberOfSections)
		{
			return false;
		}

		for (int i=0;i<ModuleInfo.nNumSections;++i)
		{
			strncpy(ModuleInfo.stSections[i].Name,(const char*)sectionHeaders[i].Name,IMAGE_SIZEOF_SHORT_NAME);
			ModuleInfo.stSections[i].pStartAddr = me.modBaseAddr+sectionHeaders[i].VirtualAddress;
			ModuleInfo.stSections[i].nSize = sectionHeaders[i].SizeOfRawData;
		}
		delete[] sectionHeaders;
		vecModule.push_back(ModuleInfo);
	} while (Module32Next(hSnap,&me));
	CloseHandle(hSnap);



	PBYTE	Address = NULL;
	MEMORY_BASIC_INFORMATION	info = {0};
	int	nItem = 0;
	while (VirtualQueryEx(hProcess,Address,&info,sizeof(info)) == sizeof(info))
	{
		char szBuffer[100] = {0};
		sprintf(szBuffer,"0x%08X",Address);
		m_ListMemory.InsertItem(nItem,szBuffer);	//块基地址
		sprintf(szBuffer,"%d",info.RegionSize);
		m_ListMemory.SetItemText(nItem,1,szBuffer);	//块大小

		for (std::vector<MODULEINFO>::iterator it=vecModule.begin();
			it!=vecModule.end();++it)
		{
			//查找该段内存属于哪个模块
			if (info.BaseAddress>=it->modBaseAddr && info.BaseAddress<=(it->modBaseAddr+it->modBaseSize))
			{
				AtlTrace("Module name:%s\n",it->szModule);
				m_ListMemory.SetItemText(nItem,2,it->szModule);
				//查找该段内存属于该模块的那个区段
				AtlTrace("BaseAddr:%08X\n",info.BaseAddress);
				if (info.BaseAddress<=it->modBaseAddr + it->nPEHeaderSize)
				{
					m_ListMemory.SetItemText(nItem,3,"PE头");
				}
				else
				{
					byte*	pRgnStart = (byte*)info.AllocationBase;
					byte*	pRgnEnd = pRgnStart + info.RegionSize;

					szBuffer[0] = '\0';
					for (int i=0;i<it->nNumSections;++i)
					{
						SECTIONINFO& SecInfo = it->stSections[i];
						byte*	pSecStart = SecInfo.pStartAddr;
						byte*	pSecEnd = pSecStart + SecInfo.nSize;
 						AtlTrace("Section Name:%s,Section startaddr:%08x,End:%X\n",SecInfo.Name,SecInfo.pStartAddr,SecInfo.pStartAddr+SecInfo.nSize);
						if (info.BaseAddress>=SecInfo.pStartAddr 
							&& info.BaseAddress<=SecInfo.pStartAddr+SecInfo.nSize)
						{
							m_ListMemory.SetItemText(nItem,3,SecInfo.Name);
							break;
						}
// 						if ((pRgnStart>=pSecStart && pRgnStart<=pSecEnd)
// 							|| (pRgnEnd>=pSecStart && pRgnEnd<=pSecEnd)
// 							|| (pSecStart>=pRgnStart && pSecStart<=pRgnEnd)
// 							|| (pSecEnd>=pRgnStart && pSecEnd<=pRgnEnd))
// 						{
// 							strcat(szBuffer,SecInfo.Name);
// 						}
					}
// 					m_ListMemory.SetItemText(nItem,3,szBuffer);
				}
				break;
			}
		}
		// 			sprintf(szBuffer,"%X",info.Protect);
		// 			m_ListMemory.SetItemText(nItem,6,szBuffer);
		if (info.Protect == 0 || (info.Protect & PAGE_NOACCESS))	//访问
		{
			strcpy(szBuffer,"NOACCESS");
		}
		else
		{
			szBuffer[0] = '\0';
			if (info.Protect & PAGE_EXECUTE)
			{
				strcat(szBuffer,"PAGE_EXECUTE ");
			}
			else if (info.Protect & PAGE_EXECUTE_READ)
			{
				strcat(szBuffer,"PAGE_EXECUTE_READ ");
			}
			else if (info.Protect & PAGE_EXECUTE_READWRITE)
			{
				strcat(szBuffer,"PAGE_EXECUTE_READWRITE ");
			}
			else if (info.Protect & PAGE_EXECUTE_WRITECOPY)
			{
				strcat(szBuffer,"PAGE_EXECUTE_WRITECOPY ");
			}
// 			if (info.Protect & PAGE_NOACCESS)
// 			{
// 				strcat(szBuffer,"PAGE_NOACCESS ");
// 			}
			else if (info.Protect & PAGE_READONLY)
			{
				strcat(szBuffer,"PAGE_READONLY ");
			}
			else if (info.Protect & PAGE_READWRITE)
			{
				strcat(szBuffer,"PAGE_READWRITE ");
			}
			else if (info.Protect & PAGE_WRITECOPY)
			{
				strcat(szBuffer,"PAGE_WRITECOPY ");
			}

			if (info.Protect & PAGE_GUARD)
			{
				strcat(szBuffer,"PAGE_GUARD ");
			}
			else if (info.Protect & PAGE_NOCACHE)
			{
				strcat(szBuffer,"PAGE_NOCACHE ");
			}
			else if (info.Protect & PAGE_WRITECOMBINE)
			{
				strcat(szBuffer,"PAGE_WRITECOMBINE");
			}
		}
		m_ListMemory.SetItemText(nItem,6,szBuffer);

		switch (info.Type)
		{
		case MEM_IMAGE:
			m_ListMemory.SetItemText(nItem,5,"MEM_IMAGE");
			if (GetMappedFileName(hProcess,info.BaseAddress,szBuffer,sizeof(szBuffer)))
			{
				m_ListMemory.SetItemText(nItem,8,szBuffer);
			}
			break;
		case MEM_MAPPED:
			m_ListMemory.SetItemText(nItem,5,"MEM_MAPPED");
			if (GetMappedFileName(hProcess,info.BaseAddress,szBuffer,sizeof(szBuffer)))
			{
				m_ListMemory.SetItemText(nItem,8,szBuffer);
			}
			break;
		case MEM_PRIVATE:
			m_ListMemory.SetItemText(nItem,5,"MEM_PRIVATE");
			if (GetMappedFileName(hProcess,info.BaseAddress,szBuffer,sizeof(szBuffer)))
			{
				m_ListMemory.SetItemText(nItem,8,szBuffer);
			}
			break;
		default:
			/*_asm int 3;*/
			break;
		}

		nItem++;
		Address += info.RegionSize;
	}
	//CloseHandle(hProcess);
	RefreshMemory2();
	return TRUE;

}

BOOL CMemListDlg::RefreshMemory2()
{
	m_MemInfoVec.clear();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,m_nPid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	//获取进程中所有模块和模块信息
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,m_nPid);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	MODULEENTRY32	me = {0};
	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hSnap,&me))
	{
		return FALSE;
	}

	std::vector<MODULEINFO>	vecModule;
	do 
	{
		MODULEINFO	ModuleInfo = {0};
		ModuleInfo.modBaseAddr = me.modBaseAddr;
		ModuleInfo.modBaseSize = me.modBaseSize;
		strcpy(ModuleInfo.szModule,me.szModule);

		//读取dos头
		IMAGE_DOS_HEADER dosHeader;
		SIZE_T	nRead;	
		if (!ReadProcessMemory(hProcess,me.modBaseAddr,&dosHeader,sizeof(IMAGE_DOS_HEADER),&nRead) 
			|| nRead != sizeof(IMAGE_DOS_HEADER)
			|| dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}

		//读取PE文件头
		IMAGE_NT_HEADERS ntHeader;
		if (!ReadProcessMemory(hProcess,me.modBaseAddr+dosHeader.e_lfanew,&ntHeader,sizeof(IMAGE_NT_HEADERS),&nRead) 
			|| nRead != sizeof(IMAGE_NT_HEADERS)
			|| ntHeader.Signature != IMAGE_NT_SIGNATURE)
		{
			return false;
		}
		//判断区段数量是否正确
		if (ntHeader.FileHeader.NumberOfSections<0
			|| ntHeader.FileHeader.NumberOfSections>96)
		{
			return false;
		}
		ModuleInfo.nNumSections = ntHeader.FileHeader.NumberOfSections;

		//模块入口点
		ModuleInfo.vecEntry.push_back((BYTE*)(ntHeader.OptionalHeader.ImageBase + ntHeader.OptionalHeader.AddressOfEntryPoint));

		//从模块开始到区段表结束之前的大小
		ModuleInfo.nPEHeaderSize = dosHeader.e_lfanew 
			+ sizeof(IMAGE_NT_HEADERS) 
			+ sizeof(IMAGE_SECTION_HEADER)*ModuleInfo.nNumSections;

		//读取所有的区段头
		IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[ntHeader.FileHeader.NumberOfSections];
		if (!ReadProcessMemory(hProcess,me.modBaseAddr+dosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS),sectionHeaders,sizeof(IMAGE_SECTION_HEADER)*ntHeader.FileHeader.NumberOfSections,&nRead)
			|| nRead != sizeof(IMAGE_SECTION_HEADER)*ntHeader.FileHeader.NumberOfSections)
		{
			return false;
		}

		for (int i=0;i<ModuleInfo.nNumSections;++i)
		{
			strncpy(ModuleInfo.stSections[i].Name,(const char*)sectionHeaders[i].Name,IMAGE_SIZEOF_SHORT_NAME);
			ModuleInfo.stSections[i].pStartAddr = me.modBaseAddr+sectionHeaders[i].VirtualAddress;
			//ModuleInfo.stSections[i].nSize = sectionHeaders[i].SizeOfRawData;
			ModuleInfo.stSections[i].nSize = sectionHeaders[i].Misc.VirtualSize;
		}
		delete[] sectionHeaders;
		vecModule.push_back(ModuleInfo);
	} while (Module32Next(hSnap,&me));
	CloseHandle(hSnap);


	PBYTE	Address = NULL;
	MEMORY_BASIC_INFORMATION	info = {0};
	while (VirtualQueryEx(hProcess,Address,&info,sizeof(info)) == sizeof(info))
	{
		//AtlTrace("%08X\n",Address);
		MEMRNGINFO	MemInfo = {0};
		MemInfo.pStartAddr = Address;	//起始地址
		MemInfo.dwAccess = info.Protect;	//访问属性
		MemInfo.dwInitial = info.AllocationProtect;		//初始访问属性
		MemInfo.dwType = info.Type;		//类型
		MemInfo.dwSize = info.RegionSize - (Address - (BYTE*)info.BaseAddress);

		byte*	pRgnStart = MemInfo.pStartAddr;
		byte*	pRgnEnd = pRgnStart + MemInfo.dwSize;
		
		//查找该段内存属于哪个模块
		for (std::vector<MODULEINFO>::iterator it=vecModule.begin();
			it!=vecModule.end();++it)
		{
			MODULEINFO& info = *it;
			//查找该段内存属于哪个模块
			if (pRgnStart<info.modBaseAddr || pRgnStart>=(info.modBaseAddr+info.modBaseSize))
			{
				continue;
			}

			MemInfo.strOwner = info.szModule;

			AtlTrace("RgnDtart:%08X\n",pRgnStart);

			if (pRgnStart == info.modBaseAddr)
			{
				MemInfo.strSectionName = "PE头";
			}

			//查找该段内存属于哪个区段
			for (int i=0;i<info.nNumSections;++i)
			{
				SECTIONINFO& SecInfo = info.stSections[i];
				byte*	pSecStart = SecInfo.pStartAddr;
				byte*	pSecEnd = pSecStart + SecInfo.nSize;
				AtlTrace("SecStart:%08X,SecEnd:%08X\n",pSecStart,pSecEnd);

				if (pRgnStart == pSecStart)
				{
					MemInfo.strSectionName = SecInfo.Name;
				}
				else if (pSecStart>pRgnStart && pSecStart<pRgnEnd)
				{
					//MemInfo.strSectionName = "";
					MemInfo.dwSize = pSecStart - pRgnStart;
					break;
				}
			}

			for each (BYTE* it in info.vecEntry)
			{
				if (it>=MemInfo.pStartAddr && it<(MemInfo.pStartAddr + MemInfo.dwSize))
				{
					MemInfo.vecEntry.push_back(it);
				}
			}

			break;
		}
		m_MemInfoVec.push_back(MemInfo);
		Address += MemInfo.dwSize;
		AtlTrace("%X\n",MemInfo.dwSize);
	}


	int nItem=0;
	for (std::vector<MEMRNGINFO>::iterator it=m_MemInfoVec.begin();
		it!=m_MemInfoVec.end();++it)
	{
		char szBuffer[100] = {0};
		sprintf(szBuffer,"%08X",it->pStartAddr);
		m_ListMemory.InsertItem(nItem,szBuffer);	//内存块起始地址
		sprintf(szBuffer,"%X",it->dwSize);
		m_ListMemory.SetItemText(nItem,1,szBuffer);	//内存块大小
		m_ListMemory.SetItemText(nItem,2,it->strOwner.c_str());	//所属模块
		m_ListMemory.SetItemText(nItem,3,it->strSectionName.c_str());	//所属区段
		switch (it->dwType)
		{
		case MEM_IMAGE:
			m_ListMemory.SetItemText(nItem,5,"MEM_IMAGE");
			if (GetMappedFileName(hProcess,it->pStartAddr,szBuffer,sizeof(szBuffer)))
			{
				m_ListMemory.SetItemText(nItem,8,szBuffer);
			}
			break;
		case MEM_MAPPED:
			m_ListMemory.SetItemText(nItem,5,"MEM_MAPPED");
			if (GetMappedFileName(hProcess,it->pStartAddr,szBuffer,sizeof(szBuffer)))
			{
				m_ListMemory.SetItemText(nItem,8,szBuffer);
			}
			break;
		case MEM_PRIVATE:
			m_ListMemory.SetItemText(nItem,5,"MEM_PRIVATE");
// 			if (GetMappedFileName(hProcess,it->pStartAddr,szBuffer,sizeof(szBuffer)))
// 			{
// 				m_ListMemory.SetItemText(nItem,8,szBuffer);
// 			}
			break;
		default:
			/*_asm int 3;*/
			break;
		}

		FormatAccess(it->dwAccess,szBuffer);
		m_ListMemory.SetItemText(nItem,6,szBuffer);
		FormatAccess(it->dwInitial,szBuffer);
		m_ListMemory.SetItemText(nItem,7,szBuffer);

		++nItem;

	}
	//CloseHandle(hProcess);
	return TRUE;
}

void CMemListDlg::FormatAccess( DWORD dwAccess,char* szAccess )
{
	if (dwAccess == 0 || (dwAccess & PAGE_NOACCESS))	//访问
	{
		strcpy(szAccess,"NOACCESS");
	}
	else
	{
		szAccess[0] = '\0';
		if (dwAccess & PAGE_EXECUTE)
		{
			strcat(szAccess,"PAGE_EXECUTE ");
		}
		else if (dwAccess & PAGE_EXECUTE_READ)
		{
			strcat(szAccess,"PAGE_EXECUTE_READ ");
		}
		else if (dwAccess & PAGE_EXECUTE_READWRITE)
		{
			strcat(szAccess,"PAGE_EXECUTE_READWRITE ");
		}
		else if (dwAccess & PAGE_EXECUTE_WRITECOPY)
		{
			strcat(szAccess,"PAGE_EXECUTE_WRITECOPY ");
		}
		else if (dwAccess & PAGE_READONLY)
		{
			strcat(szAccess,"PAGE_READONLY ");
		}
		else if (dwAccess & PAGE_READWRITE)
		{
			strcat(szAccess,"PAGE_READWRITE ");
		}
		else if (dwAccess & PAGE_WRITECOPY)
		{
			strcat(szAccess,"PAGE_WRITECOPY ");
		}

		if (dwAccess & PAGE_GUARD)
		{
			strcat(szAccess,"PAGE_GUARD ");
		}
		else if (dwAccess & PAGE_NOCACHE)
		{
			strcat(szAccess,"PAGE_NOCACHE ");
		}
		else if (dwAccess & PAGE_WRITECOMBINE)
		{
			strcat(szAccess,"PAGE_WRITECOMBINE");
		}
	}

}


LRESULT CMemListDlg::OnNMDblclkListmemory(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/)
{
	BOOL tmp;
	OnCloseCmd(NULL,IDOK,NULL,tmp);

	return 0;
}
