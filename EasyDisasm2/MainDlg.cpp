#include "stdafx.h"
#include "MainDlg.h"
#include <memory>
#include <vector>
#include "AsmDlg.h"
#include "x86Analysis.h"
#include <thread>

LRESULT CMainDlg::OnMemList( WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/ )
{
	CMemListDlg dlg;
	dlg.m_nPid = m_nPid;
	if (dlg.DoModal()!=IDOK)
	{
		return 0;
	}

	info = dlg.m_MemInfoVec[dlg.m_nIndex];
	DisasmAndShow(info);
	return 0;
}

bool CMainDlg::DisasmAndShow( CMemListDlg::MEMRNGINFO& info )
{
	m_vecCode.resize(info.dwSize);
	m_StartAddr = (uint32)info.pStartAddr;
	SIZE_T	nRead = 0;
	if (!Toolhelp32ReadProcessMemory(m_nPid,info.pStartAddr,m_vecCode.data(),info.dwSize,&nRead)
		|| nRead != info.dwSize)
	{
		return false;
	}

	std::thread thd([this,&info]()
	{
		x86Analysis analysis(m_vecCode.data(),info.dwSize,m_StartAddr);
		std::vector<std::string> asmcode;
		analysis.Process(asmcode);

		m_ListDisasm.ResetContent();

		for each (std::string s in asmcode)
		{
			m_ListDisasm.AddString(s.c_str());
		}
		return;
	});

	thd.detach();

	return true;
}

LRESULT CMainDlg::OnLbnDblclkListdisasm(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	int nIndex = m_ListDisasm.GetCurSel();
	if (nIndex == -1)
	{
		return 0;
	}

	char szBuffer[100];
	if (m_ListDisasm.GetText(nIndex,szBuffer)<=0)
	{
		return 0;
	}

	unsigned long ulAddr = 0;
	sscanf(szBuffer,"%08X",&ulAddr);

	CAsmDlg dlg;
	dlg.m_vecCode = m_vecCode;
	dlg.m_StartAddr = m_StartAddr;
	dlg.m_TargetAddr = ulAddr;
	dlg.m_nPid = m_nPid;
	if (dlg.DoModal()!=IDOK)
	{
		return 0;
	}

	DisasmAndShow(info);
	return 0;
}
