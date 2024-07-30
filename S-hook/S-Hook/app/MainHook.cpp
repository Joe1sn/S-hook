#include "../S-Hook.h"

#include "../hde/hde64.h"
#include "../utils/Crypto.hpp"
#include "../utils/Memory.hpp"

size_t SHook::calcPollutedCodeSize(LPVOID oldFunction) {
	char* p = reinterpret_cast<PCHAR>(oldFunction);
	hde64s hde64;
	size_t i = 0, totalLen = 0;
	for (; totalLen < SHook::jmpCodeSize; p += i)
	{
		i = hde64_disasm(p, &hde64);
		totalLen += i;
	}
	return totalLen;
}

void SHook::createHook(std::string label, LPVOID oldFunction, LPVOID newFunction, LPVOID* oldFuncBackup) {


	//1. calc polluted code size
	size_t pollutedLen = SHook::calcPollutedCodeSize(oldFunction);
	size_t bufferSpace = pollutedLen + SHook::jmpCodeSize; bufferSpace++;	//prevent overflow by one

	//2. allocate space to store polluted size
	DWORD oldProtect = 0;
	//2.1 if ptr is null
	if (*oldFuncBackup == nullptr) {
		*oldFuncBackup = new CHAR[bufferSpace];
		VirtualProtect(*oldFuncBackup, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect);
	}
	if (*oldFuncBackup == nullptr) {
		std::cout << std::hex << GetLastError() << std::endl;
		return;
	}
	//2.2 create heap struct
	auto bkBlock = new codeBlock;
	auto PhookCode = new jmpCode(reinterpret_cast<DWORD64>(newFunction));
	DWORD64 realOldFuncAddr = 0;
	bkBlock->pollutedLen = pollutedLen;
	bkBlock->buffer = *oldFuncBackup;
	bkBlock->Phookcode = PhookCode;
	bkBlock->newFuncAddr = newFunction;
	//parser asm code
	if (reinterpret_cast<PBYTE>(oldFunction)[0] == 0xE9) {	//jmp #inst
		realOldFuncAddr += reinterpret_cast<DWORD64>(&reinterpret_cast<PBYTE>(oldFunction)[1]);
		realOldFuncAddr += 5 + Memory::ReadDWORD32(&reinterpret_cast<PBYTE>(oldFunction)[1]);
		bkBlock->oldFuncAddr = reinterpret_cast<LPVOID>(realOldFuncAddr);
	}
	else if (reinterpret_cast<PBYTE>(oldFunction)[0] == 0x48 &&
		reinterpret_cast<PBYTE>(oldFunction)[1] == 0xff &&
		reinterpret_cast<PBYTE>(oldFunction)[2] == 0x25	) {	//jmp ptr
		realOldFuncAddr += reinterpret_cast<DWORD64>(&reinterpret_cast<PBYTE>(oldFunction)[3] + sizeof(DWORD));
		realOldFuncAddr += Memory::ReadDWORD32(&reinterpret_cast<PBYTE>(oldFunction)[3]);
		realOldFuncAddr = Memory::ReadDWORD64(reinterpret_cast<LPVOID>(realOldFuncAddr));
		bkBlock->oldFuncAddr = reinterpret_cast<LPVOID>(realOldFuncAddr);

	}
	else
		bkBlock->oldFuncAddr = oldFunction;
	//2.3 create label
	SHook::xBuffer.insert(std::make_pair(
		Crypto::cHash(label.c_str(), label.length()),
		bkBlock
	));

	//3. transfer polluted code
	//3.1 generate jmp back code
	jmpCode jmpBack(reinterpret_cast<DWORD64>(bkBlock->oldFuncAddr) + pollutedLen);
	//3.2 copy polluted code and jmp back code
	RtlCopyMemory(*oldFuncBackup, bkBlock->oldFuncAddr, pollutedLen);
	RtlCopyMemory(
		reinterpret_cast<LPVOID>(
			reinterpret_cast<DWORD64>(*oldFuncBackup) + pollutedLen),
		&jmpBack, SHook::jmpCodeSize);
}
BOOL SHook::enableHook(std::string label) {
	//1. calc hash
	unsigned int labelHash = Crypto::cHash(label.c_str(), label.length());
	PcodeBlock info = SHook::xBuffer[labelHash];
	
	//2 overwrite
	//2.1 make sure old function have proper access privilege
	DWORD oldprotect;
	VirtualProtect(info->oldFuncAddr, info->pollutedLen, PAGE_EXECUTE_READWRITE, &oldprotect);
	//2.2 copy hook jmp code
	RtlCopyMemory(info->oldFuncAddr, info->Phookcode, SHook::jmpCodeSize);

	return TRUE;
}

BOOL SHook::disableHook(std::string label) {
	//1. calc hash
	unsigned int labelHash = Crypto::cHash(label.c_str(), label.length());
	PcodeBlock info = SHook::xBuffer[labelHash];
	
	//2 overwrite
	//2.1 make sure old function have proper access privilege
	DWORD oldprotect;
	VirtualProtect(info->oldFuncAddr, info->pollutedLen, PAGE_EXECUTE_READWRITE, &oldprotect);
	//2.2 copy hook jmp code
	RtlCopyMemory(info->oldFuncAddr, info->buffer, SHook::jmpCodeSize);

	return TRUE;
}

BOOL SHook::deleteHook(std::string label) {
	SHook::disableHook(label);
	unsigned int labelHash = Crypto::cHash(label.c_str(), label.length());
	SHook::xBuffer.erase(labelHash);
	return TRUE;
}