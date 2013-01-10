#pragma once
#include "atlwin.h"
#include <atlctrls.h>
#include <TlHelp32.h>
#include <Psapi.h>
class CProcessListDlg :
	public CDialogImpl<CProcessListDlg>
{
public:
	CProcessListDlg(void){}
	~CProcessListDlg(void){}

	enum { IDD = IDD_DIALOGPROCESSLIST };

	BEGIN_MSG_MAP(CMemListDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		NOTIFY_HANDLER(IDC_LISTPROCESS, NM_DBLCLK, OnNMDblclkListprocess)
	END_MSG_MAP()

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnNMDblclkListprocess(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/);

	CListViewCtrl m_ProcessList;
	int m_nPid;
};

