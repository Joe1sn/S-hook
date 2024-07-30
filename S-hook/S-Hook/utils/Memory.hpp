#pragma once
#include <Windows.h>

namespace Memory {
	DWORD ReadDWORD32(LPVOID Addr) {
		DWORD ret = 0;
		ret += *reinterpret_cast<PDWORD>(Addr);
		return ret;
	}

	DWORD64 ReadDWORD64(LPVOID Addr) {
		DWORD64 ret = 0;
		ret += *reinterpret_cast<PDWORD64>(Addr);
		return ret;
	}
}