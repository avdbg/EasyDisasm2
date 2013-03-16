#include "stdafx.h"
#include "x86Analysis.h"
#include "util.h"
#include <algorithm>


void x86Analysis::GetBlock( uint32 uEntry )
{
	assert(IsAddrValid(uEntry));
	if (!IsAddrValid(uEntry))
	{
		return;
	}

	CPU_ADDR	curAddr;
	curAddr.addr32.offset = uEntry;
	uint32 uEnd = 0;

	ScopeExit extAddBlock([uEntry,&uEnd,this]()
	{
		assert(uEntry != 0);
		assert(uEnd != 0);
		CODEBLOCK block = {uEntry,uEnd};
		AddBlock(block);
	});

	for (unsigned i=uEntry-m_uStartVA;i<m_uCodeSize;)
	{
		x86dis_insn* insn = (x86dis_insn*)m_Decoder.decode(m_pCode+i,m_uCodeSize-i,curAddr);

		//const char* pcsIns = m_Decoder.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD);
		//printf("%08X\t%s\n",curAddr.addr32.offset, pcsIns);
		i += insn->size;
		curAddr.addr32.offset += insn->size;

		switch (IsBranch(insn))
		{
		case BR_RET:
			uEnd = CodeOffset2VA(m_pCode + i);
			return;
		case BR_JMP:
			{
				CPU_ADDR addr = branchAddr(insn);
				AddEntry(addr.addr32.offset);
				uEnd = CodeOffset2VA(m_pCode + i);
				return;
			}
		case BR_JCC:
			{
				CPU_ADDR addr = branchAddr(insn);
				AddEntry(addr.addr32.offset);
				uEnd = CodeOffset2VA(m_pCode + i);
				AddEntry(uEnd);
				return;
			}
		case BR_CALL:
			{
				CPU_ADDR addr = branchAddr(insn);
				AddEntry(addr.addr32.offset);
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

	for (byte* i = m_pCode; i < m_pCode+m_uCodeSize;)
	{
		uint32 length = m_pCode+m_uCodeSize-i;
		// 检查push ebp;mov ebp,sp
		if (
			length > 3 &&		// 剩的代码不超过3字节的话就不检查了
			*i == 0x55 &&			// 0x55为push ebp的机器码 
			( (*(i+1) == 0x8B && *(i+2) == 0xEC) || (*(i+1) == 0x89 && *(i+2) == 0xE5) ) // 两种mov ebp,esp的编码方式
			)
		{
			AddEntry(CodeOffset2VA(i));
			i += 3;
			continue;
		}


		// 检查push ebp;mov eax,[esp+xx]
		if (
			length > 4 &&
			*i == 0x55 &&
			(*(i+1) == 0x8B && *(i+2) == 0x44 && *(i+3) == 0x24 )
			)
		{
			AddEntry(CodeOffset2VA(i));
			i += 4;
			continue;
		}

		// 直接就是mov eax,[esp+xx]
		if (
			length > 3 &&
			(*i == 0x8B && *(i+1) == 0x44 && *(i+2) == 0x24 )
			)
		{
			AddEntry(CodeOffset2VA(i));
			i += 3;
			continue;
		}

		// enter xx,0指令
		if (length > 4 && *i == 0xC8 && *(i+3) == 0x00 )
		{
			AddEntry(CodeOffset2VA(i));
			i += 4;
			continue;
		}

		// mov exb,esp
		if (length > 2 && *i == 0x8B && *(i+1) == 0xDC)
		{
			AddEntry(CodeOffset2VA(i));
			i += 2;
			continue;
		}
		++i;
	}

	for (auto it = m_lstEntry.begin();
		it != m_lstEntry.end();++it)
	{
		GetBlock(*it);
	}

	std::sort(m_vecBlocks.begin(),m_vecBlocks.end(),
		[](CODEBLOCK& a,CODEBLOCK& b)->bool
	{
		assert(a.Start != b.Start);
		assert(a.End != b.End);
		return a.Start < b.Start;
	});

	return true;
}

void x86Analysis::AddBlock( const CODEBLOCK& block )
{
	std::vector<CODEBLOCK>::iterator itBefore = m_vecBlocks.begin();

	for (auto it = m_vecBlocks.begin();
		it != m_vecBlocks.end();++it)
	{
		CODEBLOCK old = *it;
		if (old.Start == block.Start)
		{
			if (old.End == block.End)
			{
				return;
			}

			if (old.End > block.End)
			{
				CODEBLOCK tmp1,tmp2;
				m_vecBlocks.erase(it);
				tmp1 = block;
				tmp2.Start = block.End;
				tmp2.End = old.End;
				AddBlock(tmp1);
				AddBlock(tmp2);
				return;
			}

			CODEBLOCK tmp1,tmp2;
			m_vecBlocks.erase(it);
			tmp1 = old;
			tmp2.Start = old.End;
			tmp2.End = block.End;
			AddBlock(tmp1);
			AddBlock(tmp2);
			return;
		}

		if (block.Start > old.Start && block.Start < old.End)
		{
			if (block.End == old.End)
			{
				CODEBLOCK tmp1,tmp2;
				tmp1.Start = old.Start;
				tmp1.End = block.Start;
				tmp2 = block;
				AddBlock(tmp1);
				AddBlock(tmp2);
				return;
			}

			if (block.End < old.End)
			{
				CODEBLOCK tmp1,tmp2,tmp3;
				tmp1.Start = old.Start;
				tmp1.End = block.Start;
				tmp2 = block;
				tmp3.Start = block.End;
				tmp3.End = old.End;
				AddBlock(tmp1);
				AddBlock(tmp2);
				AddBlock(tmp3);
				return;
			}

			CODEBLOCK tmp1,tmp2,tmp3;
			tmp1.Start = old.Start;
			tmp1.End = block.Start;
			tmp2.Start = block.Start;
			tmp2.End = old.End;
			tmp3.Start = old.End;
			tmp3.End = block.End;
			AddBlock(tmp1);
			AddBlock(tmp2);
			AddBlock(tmp3);
			return;
		}

		if (old.Start > block.Start && old.Start < block.End)
		{
			if (old.End == block.End)
			{
				CODEBLOCK tmp1,tmp2;
				tmp1.Start = block.Start;
				tmp1.End = old.Start;
				tmp2 = old;
				AddBlock(tmp1);
				AddBlock(tmp2);
				return;
			}

			if (old.End < block.End)
			{
				CODEBLOCK tmp1,tmp2,tmp3;
				tmp1.Start = block.Start;
				tmp1.End = old.Start;
				tmp2 = old;
				tmp3.Start = old.End;
				tmp3.End = block.End;
				AddBlock(tmp1);
				AddBlock(tmp2);
				AddBlock(tmp3);
				return;
			}

			CODEBLOCK tmp1,tmp2,tmp3;
			tmp1.Start = block.Start;
			tmp1.End = old.Start;
			tmp2.Start = old.Start;
			tmp2.End = block.End;
			tmp3.Start = block.End;
			tmp3.End = old.End;
			AddBlock(tmp1);
			AddBlock(tmp2);
			AddBlock(tmp3);
			return; 
		}
	}

	m_vecBlocks.push_back(block);
}
