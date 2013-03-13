#pragma once
#include "atlwin.h"

#include <vector>
#include <x86dis.h>
#include <x86asm.h>

class CAsmDlg : public CDialogImpl<CAsmDlg>
{
public:
	enum { IDD = IDD_DIALOGASM};

	BEGIN_MSG_MAP(CAsmDlg)
		COMMAND_HANDLER(IDOK, BN_CLICKED, OnBnClickedOk)
		MESSAGE_HANDLER(WM_CLOSE, OnClose)
		COMMAND_HANDLER(IDCANCEL, BN_CLICKED, OnBnClickedCancel)
		COMMAND_HANDLER(IDC_EDITADDRESS, EN_CHANGE, OnEnChangeEditaddress)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
	END_MSG_MAP()

	CAsmDlg(void)
		:m_Decoder(X86_OPSIZE32,X86_ADDRSIZE32),
	m_Encoder(X86_OPSIZE32,X86_ADDRSIZE32){};
	~CAsmDlg(void){};
	LRESULT OnBnClickedOk(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnBnClickedCancel(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);

	void ShowDasm();

	x86asm	m_Encoder;
	x86dis	m_Decoder;

	int	m_nPid;

	uint32	m_StartAddr;
	uint32	m_TargetAddr;
	int		m_nTargetSize;
	std::vector<byte> m_vecCode;
	LRESULT OnEnChangeEditaddress(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
};

