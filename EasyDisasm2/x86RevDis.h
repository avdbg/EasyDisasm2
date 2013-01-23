#pragma once

#include <map>
#include <list>
#include <x86dis.h>

class x86RevDis
{
public:
	x86RevDis(byte* pCode, unsigned uSize, uint32 uStartAddr, uint32 uEpAddr)
		:m_decoder(X86_OPSIZE32,X86_ADDRSIZE32),
		m_pCode(pCode),m_uSize(uSize),
		m_uStartAddr(uStartAddr)
	{
		m_lstDisaddr.clear();
		m_lstDisaddr.push_back(uEpAddr);
	};
	~x86RevDis(void){};

	x86dis	m_decoder;
	byte* m_pCode;
	unsigned m_uSize;
	uint32 m_uStartAddr;
	std::list<uint32> m_lstDisaddr;
	std::map<uint32,x86dis_insn> m_mapResult;

	enum branch_enum_t				//用于判断是否是转移指令
	{
		br_nobranch,				// 没有分支
		br_jump,
		br_return,
		br_call,
		br_jXX
	};

	void AddDisaddr(uint32 uAddr)
	{
		m_lstDisaddr.push_back(uAddr);
	}
	void RevDisasm(uint32 uStartAddr, uint32 uCurAddr);
	branch_enum_t isBranch(x86dis_insn* opcode);
	CPU_ADDR branchAddr(x86dis_insn *opcode);
	void Process(void);

};

