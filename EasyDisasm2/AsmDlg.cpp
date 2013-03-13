#include "StdAfx.h"
#include "AsmDlg.h"
#include <functional>


class defer
{
public:
	defer(std::function<void()> DeferFun)
		:m_DeferFun(DeferFun){}

	~defer()
	{
		if (m_DeferFun != NULL)
		{
			m_DeferFun();
		}
	}
	void Reset(){m_DeferFun = NULL;}
protected:
private:
	defer(defer&){}
	void operator=(defer&){}
	std::function<void()> m_DeferFun;
};

LRESULT CAsmDlg::OnBnClickedOk(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	HANDLE hProcess = NULL;
	asm_insn* pAsmInsn = m_Encoder.alloc_insn();
	defer([&]()
	{
		if (hProcess)
		{
			CloseHandle(hProcess);
		}
	});
	char szAsm[100] = {0};
	GetDlgItemText(IDC_EDITINSN,szAsm,100);
	if (!m_Encoder.translate_str(pAsmInsn,szAsm))
	{
		MessageBox(m_Encoder.get_error_msg());
		return 0;
	}

	CPU_ADDR addr = {0};
	addr.addr32.offset = m_TargetAddr;
	asm_code* pAsmCode = m_Encoder.encode(pAsmInsn,X86ASM_NULL,addr);
	if (!pAsmCode)
	{
		MessageBox(m_Encoder.get_error_msg());
		return 0;
	}

	hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,FALSE,m_nPid);
	if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
	{
		MessageBox("打开目标进程失败");
		return 0;
	}

	asm_code* pShort = pAsmCode;
	bool bFind = false;
	SIZE_T	nWritten = 0;

	do 
	{
		if (pAsmCode->size == m_nTargetSize)
		{
			bFind = true;
			if (!WriteProcessMemory(hProcess,(LPVOID)m_TargetAddr,pAsmCode->data,pAsmCode->size,&nWritten))
			{
				MessageBox("写入数据失败");
				return 0;
			}
			break;
		}

		if (pAsmCode->size<pShort->size)
		{
			pShort = pAsmCode;
		}
		pAsmCode = pAsmCode->next;
	} while (pAsmCode);

	if (!bFind)
	{
		if (!WriteProcessMemory(hProcess,(LPVOID)m_TargetAddr,pShort->data,pShort->size,&nWritten))
		{
			MessageBox("写入数据失败");
			return 0;
		}
	}

	EndDialog(IDOK);
	return 0;
}


LRESULT CAsmDlg::OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	EndDialog(IDCANCEL);
	return 0;
}


LRESULT CAsmDlg::OnBnClickedCancel(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	EndDialog(IDCANCEL);
	return 0;
}

void CAsmDlg::ShowDasm()
{
	unsigned long ulAddr = 0;
	char szBuffer[10];
	if (!GetDlgItemText(IDC_EDITADDRESS,szBuffer,10))
	{
		return;
	}

	sscanf(szBuffer,"%x",&ulAddr);
	if (ulAddr<m_StartAddr || ulAddr>(m_StartAddr+m_vecCode.size()))
	{
		SetDlgItemText(IDC_EDITINSN,"Bad Address");
		return;
	}

	m_TargetAddr = ulAddr;

	byte* pCode = m_vecCode.data() + (ulAddr - m_StartAddr);

	CPU_ADDR	addr = {0};
	addr.addr32.offset = ulAddr;
	x86dis_insn* pInsn = (x86dis_insn*)m_Decoder.decode(pCode,m_vecCode.size()-(ulAddr-m_StartAddr),addr);
	m_nTargetSize = pInsn->size;
	const char* pAsm = m_Decoder.str(pInsn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD | DIS_STYLE_SIGNED);
	SetDlgItemText(IDC_EDITINSN,pAsm);
}


LRESULT CAsmDlg::OnEnChangeEditaddress(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogImpl::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	ShowDasm();

	return 0;
}


LRESULT CAsmDlg::OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	char szBuffer[10] = {0};
	sprintf(szBuffer,"%08X",m_TargetAddr);
	SetDlgItemText(IDC_EDITADDRESS,szBuffer);

	return TRUE;
}
