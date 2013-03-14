#include "stdafx.h"
#include "x86Analysis.h"


void x86Analysis::DisBlock( uint32 uEntry )
{
	CPU_ADDR	curAddr;
	curAddr.addr32.offset = uEntry;

	for (unsigned i=uEntry-m_pStartVA;i<m_uCodeSize;)
	{
		x86dis_insn* insn = (x86dis_insn*)m_Decoder.decode(m_pCode+i,m_uCodeSize-i,curAddr);

		//const char* pcsIns = m_Decoder.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD);
		//printf("%08X\t%s\n",curAddr.addr32.offset, pcsIns);
		i += insn->size;
		curAddr.addr32.offset += insn->size;

		switch (IsBranch(insn))
		{
		case BR_RET:
			return;
		case BR_JMP:
			{
				CPU_ADDR addr = branchAddr(insn);
				if (addr.addr32.offset>=m_pStartVA && addr.addr32.offset<=(m_pStartVA+m_uCodeSize))
				{
					m_lstEntry.push_back(addr.addr32.offset);
				}
				return;
			}
		case BR_JCC:
		case BR_CALL:
			{
				CPU_ADDR addr = branchAddr(insn);
				if (addr.addr32.offset>=m_pStartVA && addr.addr32.offset<=(m_pStartVA+m_uCodeSize))
				{
					m_lstEntry.push_back(addr.addr32.offset);
				}
			}
			break;
		}
	}

}

x86Analysis::BRANCHTYPE x86Analysis::IsBranch(x86dis_insn* opcode)
{
	const char *opcode_str = opcode->name;
	if (opcode_str[0] == '~')
	{
		opcode_str++;
	}
	if (opcode_str[0] == '|')
	{
		opcode_str++;
	}

	if (opcode_str[0]=='j')
	{
		if (opcode_str[1]=='m')
			return BR_JMP;
		else
			return BR_JCC;
	}
	else if ((opcode_str[0]=='l') && (opcode_str[1]=='o')  && (opcode_str[2]=='o'))
	{
		// loop opcode will be threated like a jXX
		return BR_JCC;
	}
	else if ((opcode_str[0]=='c') && (opcode_str[1]=='a'))
	{
		return BR_CALL;
	}
	else if ((opcode_str[0]=='r') && (opcode_str[1]=='e'))
	{
		return BR_RET;
	}
	else return BR_NONE;
}

CPU_ADDR x86Analysis::branchAddr(x86dis_insn *opcode)
{
	CPU_ADDR addr = {0};
	//assert(o->op[1].type == X86_OPTYPE_EMPTY);
	if (opcode->op[1].type != X86_OPTYPE_EMPTY)
	{
		return addr;
	}
	switch (opcode->op[0].type)
	{
	case X86_OPTYPE_IMM:
		{		
			addr.addr32.offset = opcode->op[0].imm;
		}
		// 	case X86_OPTYPE_FARPTR:
		// 		break;
	case X86_OPTYPE_MEM:
		{
			if (opcode->op[0].mem.hasdisp)
			{
				addr.addr32.offset = opcode->op[0].mem.disp;
			}
			else
			{
				break;
			}
		}
	default: break;
	}
	return addr;
}

bool x86Analysis::Process( void )
{
	for (auto it = m_lstEntry.begin();
		it != m_lstEntry.end();++it)
	{
		DisBlock(*it);
	}
}

void x86Analysis::AddBlock( const CODEBLOCK& block )
{
	std::vector<CODEBLOCK>::iterator itBefore = m_vecBlocks.begin();

	for (auto it = m_vecBlocks.begin();
		it != m_vecBlocks.end();++it)
	{
		if (it->Start == block.Start)
		{
			return;
		}

		if (block.Start > it->Start)
		{
			if (block.Start < it->End)
			{
				assert(it->End == block.End);
				CODEBLOCK tmp;
				tmp.Start = it->Start;
				tmp.End = block.Start;
				m_vecBlocks.erase(it);
				AddBlock(tmp);
				AddBlock(block);
				return;
			}
			itBefore = it+1;
		}
	}

	m_vecBlocks.insert(itBefore,block);
}
