#include "StdAfx.h"
#include "ProcessListDlg.h"

LRESULT CProcessListDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	CenterWindow(GetParent());
	m_ProcessList.Attach(this->GetDlgItem(IDC_LISTPROCESS));
	m_ProcessList.SetExtendedListViewStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_ProcessList.InsertColumn(0,"PID",LVCFMT_LEFT,50);
	m_ProcessList.InsertColumn(1,"Exe Name",LVCFMT_LEFT,100);
	m_ProcessList.InsertColumn(2,"Path",LVCFMT_LEFT,200);

	HANDLE hToolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hToolhelp == INVALID_HANDLE_VALUE)
	{
		this->MessageBox("获取进程快照失败");
		return	TRUE;
	}
	PROCESSENTRY32	stProcess = {0};
	stProcess.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hToolhelp, &stProcess);
	for (int i=0;Process32Next(hToolhelp, &stProcess);i++)
	{
		char	pszPid[10];
		_itoa(stProcess.th32ProcessID, pszPid,10);
		//m_processList.SetItemText(i,0,pszPid);
		m_ProcessList.InsertItem(i, pszPid);
		m_ProcessList.SetItemText(i,1,stProcess.szExeFile);
		HANDLE	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, stProcess.th32ProcessID);
		char	pszProcessPath[MAX_PATH+2];
		if (GetModuleFileNameEx(hProcess, NULL, pszProcessPath, MAX_PATH+2))
		{
			m_ProcessList.SetItemText(i, 2, pszProcessPath);
		}
		CloseHandle(hProcess);
	}

	CloseHandle(hToolhelp);

	return TRUE;

}
LRESULT CProcessListDlg::OnNMDblclkListprocess(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/)
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL tmp = FALSE;
	OnCloseCmd(NULL,IDOK,NULL,tmp);
	return 0;
}

LRESULT CProcessListDlg::OnCloseCmd( WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/ )
{
	if (wID != IDOK)
	{
		EndDialog(wID);
		return 0;
	}
	UINT index = m_ProcessList.GetSelectionMark();
	if(index == -1)
	{
		this->MessageBox("请选择一个进程");
		return 0;
	}
	char	pszPid[10];
	m_ProcessList.GetItemText(index, 0, pszPid, 10);
	m_nPid = atoi(pszPid);

	EndDialog(wID);
	return 0;

}
