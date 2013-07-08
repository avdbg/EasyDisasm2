#include "stdafx.h"
#include "x86Analysis.h"
#include "util.h"
#include <algorithm>
#include <string.h>

extern HANDLE hProcess;

x86Analysis::x86Analysis( byte* pCode, unsigned uSize, uint32 uStartAddr )
	:m_Decoder(X86_OPSIZE32,X86_ADDRSIZE32),
	m_pCode(pCode),m_uCodeSize(uSize),
	m_uStartVA(uStartAddr),cache_insn(10)
{

}

x86Analysis::~x86Analysis( void )
{

}

void x86Analysis::GetBlock( uint32 uEntry )
{
	if (!IsAddrValid(uEntry))
	{
		return;
	}

	CPU_ADDR	curAddr;
	curAddr.addr32.seg = 0;
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
		//assert(curAddr.addr32.offset != 0x00401029);
		x86dis_insn* insn = (x86dis_insn*)m_Decoder.decode(m_pCode+i,m_uCodeSize-i,curAddr);

		//const char* pcsIns = m_Decoder.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD);
		//printf("%08X\t%s\n",curAddr.addr32.offset, pcsIns);
		i += insn->size;
		curAddr.addr32.offset += insn->size;

		if (cache_insn.size()>=10)
		{
			cache_insn.pop_back();
		}
		cache_insn.push_front(*insn);

		uEnd = CodeOffset2VA(m_pCode + i);

		switch (IsBranch(insn))
		{
		case BR_RET:
			return;
		case BR_JMP:
			{
				if (IsJumpTable(insn))
				{
					// 获取跳转表地址
					BYTE* pIndexTabAddr = NULL;
					BYTE* pAddressTabAddr = (BYTE*)insn->op[0].mem.disp;
					int nIndexSize = 0;
					int nIndexTabSize = 0;
					for each (x86dis_insn insn in cache_insn)
					{
						if (insn.name == NULL)
						{
							continue;
						}

						if (strstr(insn.name,"mov")
							&& insn.op[1].type == X86_OPTYPE_MEM
							&& insn.op[0].type == X86_OPTYPE_REG
							&& pIndexTabAddr == NULL)
						{
							pIndexTabAddr = (BYTE*)insn.op[1].mem.disp;
							nIndexSize = insn.op[1].size;
							continue;
						}
						if (strstr(insn.name,"cmp")
							&& insn.op[1].type == X86_OPTYPE_IMM
							&& nIndexTabSize == 0)
						{
							nIndexTabSize = insn.op[1].imm+1;
							continue;
						}

// 						if (strstr(insn.name,""))
// 						{
// 							continue;
// 						}
					}

					if (pIndexTabAddr == NULL
						|| pAddressTabAddr == NULL
						|| nIndexTabSize == 0
						|| nIndexSize == 0)
					{
						// 构成跳转表的东西不够
						return;
					}

					BYTE pIndexTabCpy[nIndexTabSize*nIndexSize];
					SIZE_T nRead = 0;
					BOOL ret = ReadProcessMemory(hProcess,pIndexTabAddr,pIndexTabCpy,nIndexTabSize*nIndexSize,&nRead);

					int nIndex = 0;

					for (int i=0;i<nIndexTabSize*nIndexSize;i+=nIndexSize)
					{
						switch (nIndexSize)
						{
						case 1:
							{
								nIndex = pIndexTabCpy[i];
							}
							break;
						case 2:
							{
								nIndex = (WORD)pIndexTabCpy[i];
							}
							break;
						case 4:
							{
								nIndex = (DWORD)pIndexTabCpy[i];
							}
							break;
						}
						uint32 address = 0;
						ReadProcessMemory(hProcess,pAddressTabAddr+nIndex*4,&address,4,NULL);
						AtlTrace("Index:%d,Address:0x%08x\n",nIndex,address);
						AddEntry(address);
					}
// 					for ()
// 					{
// 					}
					return;
				}
				else
				{
					CPU_ADDR addr = branchAddr(insn);
					AddEntry(addr.addr32.offset);
					return;
				}
			}
		case BR_JCC:
			{
				CPU_ADDR addr = branchAddr(insn);
				//AddEntry(uEnd);
				GetBlock(uEnd);
				AddEntry(addr.addr32.offset);
				return;
			}
		case BR_CALL:
			{
				CPU_ADDR addr = branchAddr(insn);
				AddEntry(uEnd);
				AddEntry(addr.addr32.offset);
			}
			break;
		}
	}

}


uint32 x86Analysis::GetBlockSize( uint32 uEntry )
{
	if (!IsAddrValid(uEntry))
	{
		assert(false);
		return 0;
	}

	CPU_ADDR	curAddr;
	curAddr.addr32.offset = uEntry;

	for (unsigned i=uEntry-m_uStartVA;i<m_uCodeSize;)
	{
		x86dis_insn* insn = (x86dis_insn*)m_Decoder.decode(m_pCode+i,m_uCodeSize-i,curAddr);

		i += insn->size;
		curAddr.addr32.offset += insn->size;
		BRANCHTYPE type = IsBranch(insn);
		if (type == BR_JMP || type == BR_RET)
		{
			break;
		}
	}

	return curAddr.addr32.offset - uEntry;
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
			break;
		}
		// 	case X86_OPTYPE_FARPTR:
		// 		break;
	case X86_OPTYPE_MEM:
		{
			if (opcode->op[0].mem.hasdisp)
			{
				//addr.addr32.offset = opcode->op[0].mem.disp;

				ReadProcessMemory(hProcess,(LPVOID)opcode->op[0].mem.disp,&addr.addr32.offset,4,NULL);
			}
			break;
		}
// 	case X86_OPTYPE_REG:
// 		{
// 			assert(false);
// 		}
// 		break;
	default: break;
	}
	return addr;
}

bool x86Analysis::Process( std::vector<std::string>& asmcode )
{
	// TODO:添加更多函数开始的特征码
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
			uint32 va = CodeOffset2VA(i);
			AddEntry(va);
			i += GetBlockSize(va);
			continue;
		}


		// 检查push ebp;mov eax,[esp+xx]
		if (
			length > 4 &&
			*i == 0x55 &&
			(*(i+1) == 0x8B && *(i+2) == 0x44 && *(i+3) == 0x24 )
			)
		{
			uint32 va = CodeOffset2VA(i);
			AddEntry(va);
			i += GetBlockSize(va);
			continue;
		}

		// 直接就是mov eax,[esp+xx]
		if (
			length > 3 &&
			(*i == 0x8B && *(i+1) == 0x44 && *(i+2) == 0x24 )
			)
		{
			uint32 va = CodeOffset2VA(i);
			AddEntry(va);
			i += GetBlockSize(va);
			continue;
		}

		// enter xx,0指令
		if (length > 4 && *i == 0xC8 && *(i+3) == 0x00 )
		{
			uint32 va = CodeOffset2VA(i);
			AddEntry(va);
			i += GetBlockSize(va);
			continue;
		}

		// mov exb,esp
		if (length > 2 && *i == 0x8B && *(i+1) == 0xDC)
		{
			uint32 va = CodeOffset2VA(i);
			AddEntry(va);
			i += GetBlockSize(va);
			continue;
		}
		++i;
	}

	for each (uint32 entry in m_lstEntry)
	{
		GetBlock(entry);
	}

	std::sort(m_vecBlocks.begin(),m_vecBlocks.end(),
		[](CODEBLOCK& a,CODEBLOCK& b)->bool
	{
		assert(a.Start != b.Start);
		assert(a.End != b.End);
		return a.Start < b.Start;
	});

	uint32 startVA = m_uStartVA;
	char	szBuffer[100]; // FIXME：可能缓冲区溢出
	for each (const CODEBLOCK& block in m_vecBlocks)
	{
		if (startVA != block.Start)
		{
			for (uint32 i = startVA; i < block.Start; ++i)
			{
				sprintf(szBuffer,"%08X  DB %02X",i,*VA2CodeOffset(i));
				asmcode.push_back(std::string(szBuffer));
			}
		}

		DisBlock(block,asmcode);
		startVA = block.End;
	}

	FILE* f = fopen("asm.txt","a+");
	for each (std::string s in asmcode)
	{
		fprintf(f,"%s\n",s.c_str());
	}
	fclose(f);

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

void x86Analysis::DisBlock( const CODEBLOCK& block,std::vector<std::string>& asmcode )
{
	if (!IsAddrValid(block.Start))
	{
		assert(false);
		return;
	}

	CPU_ADDR	curAddr;
	curAddr.addr32.offset = block.Start;
	char szBuffer[100]; // FIXME：可能缓冲区溢出
	byte* pCodeStart = VA2CodeOffset(block.Start);

	for (unsigned i = 0;
		i < block.End - block.Start;)
	{
		x86dis_insn* insn = (x86dis_insn*)m_Decoder.decode(pCodeStart+i,m_uCodeSize-i,curAddr);

		const char* pcsIns = m_Decoder.str(insn,DIS_STYLE_HEX_ASMSTYLE | DIS_STYLE_HEX_UPPERCASE | DIS_STYLE_HEX_NOZEROPAD);
		//printf("%08X\t%s\n",curAddr.addr32.offset, pcsIns);
		sprintf(szBuffer, "%08X  %s",curAddr.addr32.offset, pcsIns);
		asmcode.push_back(std::string(szBuffer));
		i += insn->size;
		curAddr.addr32.offset += insn->size;
	}
}

bool x86Analysis::IsJumpTable( x86dis_insn* insn )
{
	const char *opcode_str = insn->name;
	if (opcode_str[0] == '~')
	{
		opcode_str++;
	}
	if (opcode_str[0] == '|')
	{
		opcode_str++;
	}

	if (opcode_str[0]!='j' || opcode_str[1]!='m')
	{
		return false;
	}

	const x86_insn_op& op0 = insn->op[0];
	if (op0.type == X86_OPTYPE_MEM 
		&& op0.mem.hasdisp 
		&& op0.mem.index != X86_REG_NO 
		&& op0.mem.scale == 4)
	{
		return true;
	}
	return false;

}

