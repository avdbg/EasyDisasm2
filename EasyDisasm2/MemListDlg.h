// aboutdlg.h : interface of the CAboutDlg class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once
#include <atlctrls.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
class CMemListDlg : public CDialogImpl<CMemListDlg>
{
public:
	enum { IDD = IDD_MEMLIST};

	BEGIN_MSG_MAP(CMemListDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		NOTIFY_HANDLER(IDC_LISTMEMORY, NM_RCLICK, OnNMRclickListmemory)
		NOTIFY_HANDLER(IDC_LISTMEMORY, NM_DBLCLK, OnNMDblclkListmemory)
	END_MSG_MAP()

// Handler prototypes (uncomment arguments if needed):
//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		CenterWindow(GetParent());
		m_ListMemory.Attach(this->GetDlgItem(IDC_LISTMEMORY));
		m_ListMemory.SetExtendedListViewStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
		m_ListMemory.InsertColumn(0,"地址",0,70);
		m_ListMemory.InsertColumn(1,"大小",0,70);
		m_ListMemory.InsertColumn(2,"属主",0,50);
		m_ListMemory.InsertColumn(3,"区段",0,50);
		m_ListMemory.InsertColumn(4,"包含",0,50);
		m_ListMemory.InsertColumn(5,"类型",0,50);
		m_ListMemory.InsertColumn(6,"访问",0,50);
		m_ListMemory.InsertColumn(7,"初始访问",0,50);
		m_ListMemory.InsertColumn(8,"映射为",0,50);
		RefreshMemory2();
		return TRUE;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		if (wID != IDOK)
		{
			EndDialog(wID);
			return 0;
		}
		m_nIndex = m_ListMemory.GetSelectionMark();
		if(m_nIndex == -1)
		{
			this->MessageBox("请选择一个内存块");
			return 0;
		}

		EndDialog(wID);
		return 0;
	}

	CListViewCtrl	m_ListMemory;
	int	m_nPid;

	typedef	struct tagSECTIONINFO
	{
		char	Name[IMAGE_SIZEOF_SHORT_NAME+1];
		byte*	pStartAddr;
		DWORD	nSize;
	}SECTIONINFO;

	typedef struct tagMODULEINFO 
	{
		BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
		DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
		char    szModule[MAX_MODULE_NAME32 + 1];
		DWORD	nPEHeaderSize;
		int		nNumSections;
		SECTIONINFO	stSections[96];

		std::vector<BYTE*> vecEntry;
	}MODULEINFO;

	typedef	struct tagMEMRNGINFO 
	{
		BYTE*	pStartAddr;
		DWORD	dwSize;
		std::string	strOwner;
		std::string strSectionName;
// 		BYTE*	pSectionStart;
		DWORD	dwSectionSize;
		DWORD	dwContains;
		DWORD	dwType;
		DWORD	dwAccess;
		DWORD	dwInitial;

		std::vector<BYTE*> vecEntry;
		//std::string	strMapAs;
	}MEMRNGINFO;
	BOOL RefreshMemory();
	void FormatAccess(DWORD dwAccess,char* szAccess);
	BOOL RefreshMemory2();

	std::vector<MEMRNGINFO>	m_MemInfoVec;
	UINT m_nIndex;
	LRESULT OnNMDblclkListmemory(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/);
	LRESULT OnNMRclickListmemory(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/);
};

