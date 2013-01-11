#include "stdafx.h"
#include "MainDlg.h"
#include <memory>
#include <vector>

LRESULT CMainDlg::OnMemList( WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/ )
{
	CMemListDlg dlg;
	dlg.m_nPid = m_nPid;
	if (dlg.DoModal()!=IDOK)
	{
		return 0;
	}

	CMemListDlg::MEMRNGINFO	info = dlg.m_MemInfoVec[dlg.m_nIndex];
	DisasmAndShow(info);
	return 0;
}

bool CMainDlg::DisasmAndShow( CMemListDlg::MEMRNGINFO& info )
{
	unsigned char* pCode = new unsigned char[info.dwSize];
	std::vector<unsigned char> vecCode(info.dwSize);
	SIZE_T	nRead = 0;
	if (!Toolhelp32ReadProcessMemory(m_nPid,info.pStartAddr,vecCode.data(),info.dwSize,&nRead)
		|| nRead != info.dwSize)
	{
		return false;
	}

	CPU_ADDR	addr = {0};
	addr.addr32.seg = 0;
	addr.addr32.offset = (uint32)info.pStartAddr;
	int nIndex = 0;
	for (int i=0;i<vecCode.size();++nIndex)
	{
		x86dis_insn* insn = (x86dis_insn*)m_x86Dasm.decode(vecCode.data()+i,vecCode.size()-i,addr);
		const char* pcsIns = m_x86Dasm.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD | DIS_STYLE_SIGNED);
		//在ListView中显示
		char	szBuffer[100];
		sprintf(szBuffer,"%08X",addr.addr32.offset);	//地址
		m_ListDisasm.InsertItem(nIndex,szBuffer);
		m_ListDisasm.SetItemText(nIndex,2,pcsIns);	//汇编代码
		//地址++
		addr.addr32.offset += insn->size;
		i += insn->size;
	}
// 	_DecodedInst*	pInst = new _DecodedInst[info.dwSize];
// 	for (int i=0;i<nInst;++i)
// 	{
// 		char	szBuffer[100];
// 		sprintf(szBuffer,"%08I64X",pDinst[i].addr);
// 		m_ListDisasm.InsertItem(i,szBuffer);
// 		distorm_format(&ci,pDinst+i,pInst+i);
// 		m_ListDisasm.SetItemText(i,1,(char*)pInst[i].instructionHex.p);
// 		sprintf(szBuffer,"%s%s%s",pInst[i].mnemonic.p, pInst[i].operands.length != 0 ? " " : "", (char*)pInst[i].operands.p);
// 		m_ListDisasm.SetItemText(i,2,szBuffer);
// 	}

	return true;
}
