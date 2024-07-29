#pragma once

#include <Windows.h>
#include <map>
#include <iostream>

#pragma pack(push, 1)	// set align to 1, make "shellcode" avaliable
struct jmpCode {
	const CHAR push;
	DWORD32 lowByte;
	const DWORD32 movptr;
	DWORD32 highByte;
	const CHAR ret;

	//jmpCode(DWORD32 low, DWORD32 high)
	jmpCode(DWORD64 addr)
		: push(0x68), movptr(0x042444C7), ret(0xC3), 
		lowByte(addr), 
		highByte(addr >> 32) {}

	DWORD64 getBackAddr() {
		return this->lowByte + (static_cast<DWORD64>(this->highByte) << 32);
	}
};
#pragma pack(pop) // set default align

typedef struct
{
	LPVOID buffer;
	size_t pollutedLen;
	jmpCode* Phookcode;
	LPVOID newFuncAddr;
	LPVOID oldFuncAddr;
}codeBlock, *PcodeBlock;

namespace SHook {
	
	inline const  int jmpCodeSize = sizeof(jmpCode);

	inline std::map<unsigned int, PcodeBlock> xBuffer = {};
			//	<block hash, buffer> pointer
			//	backBuffer: buffers to store polluted assemble code
			//  Phookcode: buffers to store hook assemble code
	
	/// <summary>
	/// calculate polluted assemble code's size
	/// </summary>
	/// <param name="oldFunction">:address of function which want to hook</param>
	/// <returns>function polluted assemble code size</returns>
	size_t calcPollutedCodeSize(LPVOID oldFunction);

	/// <summary>
	/// create hook
	/// </summary>
	/// <param name="label">:marks hook related info</param>
	/// <param name="oldFunction">:function to be hooked</param>
	/// <param name="newFunction">:function that overwrite old function</param>
	/// <param name="oldFuncBackup">:reserved old function</param>
	void createHook(std::string label, LPVOID oldFunction, LPVOID newFunction, LPVOID *oldFuncBackup);

	BOOL enableHook(std::string label);
	BOOL disableHook(std::string label);
	BOOL deleteHook(std::string label);
}