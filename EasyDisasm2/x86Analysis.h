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
	uint32 m_pStartVA;

	typedef struct tagDISBLOCK
	{
		uint32 Start;
		uint32 End;
		std::vector<std::string> Disasm;
	}DISBLOCK;

	std::vector<DISBLOCK> m_vecBlocks;
	void DisBlock(uint32 uEntry);
	byte* VA2CodeOffset(uint32 va){return m_pCode + (va - m_pStartVA);}
	uint32 CodeOffset2VA(byte* offset){return m_pStartVA + (offset - m_pCode);}

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

public:
	x86Analysis(byte* pCode, unsigned uSize, uint32 uStartAddr)
		:m_Decoder(X86_OPSIZE32,X86_ADDRSIZE32){}
	~x86Analysis(void){}

	void AddEntry(uint32 uEntry){m_lstEntry.push_back(uEntry);}
	bool IsAddrDis(uint32 uAddr){}
};

