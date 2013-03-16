#include "stdafx.h"
#include "MainDlg.h"
#include <memory>
#include <vector>
#include "AsmDlg.h"
#include "x86Analysis.h"

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

	x86Analysis analysis(m_vecCode.data(),info.dwSize,m_StartAddr);
	analysis.Process();

	m_ListDisasm.DeleteAllItems();

	CPU_ADDR	addr = {0};
	addr.addr32.seg = 0;
	addr.addr32.offset = (uint32)info.pStartAddr;
	int nIndex = 0;
	for (int i=0;i<m_vecCode.size();++nIndex)
	{
		x86dis_insn* insn = (x86dis_insn*)m_x86Dasm.decode(m_vecCode.data()+i,m_vecCode.size()-i,addr);
		const char* pcsIns = m_x86Dasm.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD | DIS_STYLE_SIGNED);
		//在ListView中显示
		char	szBuffer[100];
		sprintf(szBuffer,"%08X",addr.addr32.offset);	//地址
		m_ListDisasm.InsertItem(nIndex,szBuffer);
		
		*szBuffer = '\0';
		char* tmp = szBuffer;
		for (int j=0; j < insn->size; j++)
		{
			tmp += sprintf(tmp, "%02x ", m_vecCode[j]);
		}
		m_ListDisasm.SetItemText(nIndex,1,szBuffer);	//hex
		m_ListDisasm.SetItemText(nIndex,2,pcsIns);	//汇编代码
		//地址++
		addr.addr32.offset += insn->size;
		i += insn->size;
	}
	return true;
}



LRESULT CMainDlg::OnNMRclickListdisasm(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/)
{
	int nIndex = m_ListDisasm.GetSelectedIndex();
	if (nIndex == -1)
	{
		return 0;
	}

	char szBuffer[10];
	if (m_ListDisasm.GetItemText(nIndex,0,szBuffer,10)<=0)
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
