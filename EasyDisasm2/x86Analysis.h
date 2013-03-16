#pragma once

#include "x86dis.h"
#include <list>
#include <vector>

class x86Analysis
{
private:
	x86dis	m_Decoder;
	std::list<uint32> m_lstEntry;

	byte* m_pCode;
	uint32 m_uCodeSize;
	uint32 m_uStartVA;

	typedef struct tagCODEBLOCK
	{
		uint32 Start;
		uint32 End;
	}CODEBLOCK;

	std::vector<CODEBLOCK> m_vecBlocks;
	void GetBlock(uint32 uEntry);
	byte* VA2CodeOffset(uint32 va)
	{
		assert(va >= m_uStartVA && va <= (m_uStartVA + m_uCodeSize));
		return m_pCode + (va - m_uStartVA);
	}
	uint32 CodeOffset2VA(byte* offset)
	{
		assert(offset >= m_pCode && offset <= (m_pCode + m_uCodeSize));
		return m_uStartVA + (offset - m_pCode);
	}

	void FindCodeBlock();

	enum BRANCHTYPE				//用于判断是否是转移指令
	{
		BR_NONE,				// 没有分支
		BR_JMP,
		BR_RET,
		BR_CALL,
		BR_JCC
	};
	x86Analysis::BRANCHTYPE IsBranch(x86dis_insn* opcode);
	CPU_ADDR branchAddr(x86dis_insn *opcode);
	void AddBlock(const CODEBLOCK& block);

public:
	x86Analysis(byte* pCode, unsigned uSize, uint32 uStartAddr)
		:m_Decoder(X86_OPSIZE32,X86_ADDRSIZE32),
		m_pCode(pCode),m_uCodeSize(uSize)
		,m_uStartVA(uStartAddr){}

	~x86Analysis(void){}

	bool IsAddrValid(uint32 addr)
	{return (addr >= m_uStartVA && addr <= (m_uStartVA+m_uCodeSize));}

	bool AddEntry(uint32 uEntry)
	{
		if (!IsAddrValid(uEntry))
		{
			return false;
		}

		for (auto it = m_lstEntry.begin();
			it != m_lstEntry.end();++it)
		{
			if (*it == uEntry)
			{
				return true;
			}
		}

		m_lstEntry.push_back(uEntry);
		return true;
	}
	bool IsAddrDis(uint32 uAddr){}
	bool Process(void);
};

