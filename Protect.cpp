/******************************************************************************
* 
*	Protect.cpp : anti-reverse protection tools
* 
*	C++23, CMake 3.20+
* 
*	NOTES:
*		...
* 
******************************************************************************/


#include "Protect.h"

#include <array>
#include <vector>
#include <string_view>
#include <string>
#include <algorithm>
#include <cwctype>
#include <cstring>
#include <print>

#include <intrin.h>
// WIN32_LEAN_AND_MEAN + NOMINMAX are defined in CMakeLists.txt
#include <Windows.h>

//	libs for MAC check
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

// libs for WMI check
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


// ANTI-DEBUG	===============================================================

// check if being debugged via IsDebuggerPresent
bool protect::adIsDebuggerPresent() {
	return IsDebuggerPresent() != FALSE;
}


// directly check PEB->BeingDebugged 
// in case of hooked/patched user-mode IsDebuggerPresent
bool protect::adPebFlag() {
#if defined(_M_X64)
	auto peb = reinterpret_cast<const BYTE*>(__readgsqword(0x60));
#elif defined(_M_IX86)
	auto peb = reinterpret_cast<const BYTE*>(__readfsdword(0x30));
#else
	return false;
#endif
	return peb[2] != 0;
}


// check ProcessDebugPort in NtQueryInformationProcess
// if nonzero --> debugger present
bool protect::adNtQueryDebugPort() {
	using NtQueryInformationProcess_t =
		LONG(__stdcall*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		return false;
	}

	auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
		GetProcAddress(ntdll, "NtQueryInformationProcess"));
	if (!NtQueryInformationProcess) {
		return false;
	}

	constexpr ULONG ProcessDebugPort = 7;
	ULONG_PTR debugPort = 0;
	ULONG returned = 0;

	LONG status = NtQueryInformationProcess(
		GetCurrentProcess(), 
		ProcessDebugPort, 
		&debugPort, 
		sizeof(debugPort), 
		&returned
	);

	return status == 0 && debugPort != 0;
}


// detects hardware breakpoints via GetThreadContext
bool protect::adHardwareBreakpoints() {
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// GetThreadContext is documented for suspended threads, but reading
	// the CURRENT thread's debug registers can be used to 
	// detect hardware breakpoints (Dr0-Dr3) set by a debugger.
	if (!GetThreadContext(GetCurrentThread(), &ctx)) {
		return false;
	}

	return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}


// detect single-stepping debug / breakpoints set inside loop
bool protect::adTimingAnomaly() {
	LARGE_INTEGER freq{}, start{}, end{};

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&start);

	volatile long acc = 0;
	for (int i = 0; i < 1000; ++i) {
		acc += i * i - i;
	}

	QueryPerformanceCounter(&end);

	double micros =
		(end.QuadPart - start.QuadPart) * 1'000'000.0 
		/ static_cast<double>(freq.QuadPart);

	// on real hardware this loop takes a few microseconds; a debugger
	// single-stepping through it (or a breakpoint hit inside it) blows
	// this up by 2-3 orders of magnitude
	return micros > 500.0;
}


// get combined mask of anti-debug measures
uint8_t protect::adCombinedMask() {
	uint8_t mask = 0;
	
	mask |= adIsDebuggerPresent()	? (1 << 0) : 0;
	mask |= adPebFlag()				? (1 << 1) : 0;
	mask |= adNtQueryDebugPort()	? (1 << 2) : 0;
	mask |= adHardwareBreakpoints() ? (1 << 3) : 0;
	mask |= adTimingAnomaly()		? (1 << 4) : 0;
	
	return mask;
}


// ANTI-VM	===================================================================

// checks if HV bit in cpuid is set
// false-positive from Microsoft HV (used in VBS of W10/11)
bool protect::vmCpuidHypervisorBit() {
	int info[4]{};
	__cpuid(info, 1);
	return (info[2] & (1 << 31)) != 0;
}


// checks for VM-typical vendor strings in cpuid
// works correctly after "Microsoft Hv" removal from known
bool protect::vmCpuidVendorString() {
	int info[4]{};
	__cpuid(info, 0x40000000);

	char vendor[12]{};
	
	memcpy(vendor + 0, &info[1], 4);
	memcpy(vendor + 4, &info[2], 4);
	memcpy(vendor + 8, &info[3], 4);

	// microsoft's hv commented out so program can be tested on W10/11
	static constexpr const char* known[] = {
		"VBoxVBoxVBox", "VMwareVMware", // "Microsoft Hv",
		"KVMKVMKVM\0\0\0", "XenVMMXenVMM", "prl hyperv  ", "bhyve bhyve "
	};

	for (const char* sig : known) {
		if (memcmp(vendor, sig, 12) == 0) {
			return true;
		}
	}
	
	return false;
}


// detect VM based on __cpuid() execution time
// false-positive from Microsoft HV (used in VBS of W10/11)
bool protect::vmCpuidTimingAnomaly() {
	constexpr int kSamples = 8;
	unsigned long long total = 0;

	for (int i = 0; i < kSamples; ++i) {
		int info[4]{};
		
		unsigned long long t0 = __rdtsc();
		
		__cpuid(info, 0);
		
		unsigned long long t1 = __rdtsc();
		
		total += (t1 - t0);
	}

	unsigned long long avg = total / kSamples;

	// CPUID always causes a VM exit under virtualization, which costs
	// thousands of cycles versus tens of cycles on bare metal
	return avg > 1000;
}


// check Raw System Management BIOS via GetSystemFirmwareTable
// looking for known VM vendors
// does not conflict with W10/11's VBS
bool protect::vmFirmwareTable() {
	constexpr DWORD kRsmb = 'RSMB';

	DWORD size = GetSystemFirmwareTable(kRsmb, 0, nullptr, 0);
	if (size == 0) {
		return false;
	}

	std::vector<uint8_t> buffer(size);
	if (GetSystemFirmwareTable(kRsmb, 0, buffer.data(), size) != size) {
		return false;
	}

	static constexpr std::string_view needles[] = {
		"VBOX", "VirtualBox", "innotek", "VMware", "QEMU", "Xen", "Bochs"
	};

	std::string_view haystack(reinterpret_cast<const char*>(
		buffer.data()), buffer.size()
	);

	for (auto n : needles) {
		if (haystack.find(n) != std::string_view::npos) {
			return true;
		}
	}
	return false;
}


// check OUI of MAC-address to see if it belongs to VM vendors
// See: https://dnschecker.org/mac-lookup.php
// 
// VMware				--- 00:05:69, 00:0C:29, 00:50:56 (+ 00:1C:14)
// Microsoft Hyper-V	--- 00:03:FF, 00:15:5D (RISK OF FALSE-POSITIVES)
// Oracle VirtualBox	--- 08:00:27
// KVM / QEMU / Red Hat	--- 52:54:00
// Xen / Citrix / LXC	--- 00:16:3E
// Proxmox VE			--- BC:24:11
// Parallels			--- 00:1C:42
//
bool protect::vmMacAddressOui() {
	ULONG bufLen = 15000; // recommended starting size, see GetAdaptersAddresses docs
	std::vector<uint8_t> buffer(bufLen);
	auto addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

	constexpr ULONG flags =
		GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

	DWORD result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufLen);
	if (result == ERROR_BUFFER_OVERFLOW) {
		buffer.resize(bufLen);
		addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
		result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufLen);
	}

	if (result != NO_ERROR) {
		return false;
	}

	// 3-byte OUI prefixes registered to (or long-standing conventionally
	// used by) common hypervisors' virtual NICs.
	static constexpr uint8_t known[][3] = {
		{ 0x08, 0x00, 0x27 }, // VirtualBox
		{ 0x00, 0x05, 0x69 }, // VMware
		{ 0x00, 0x0C, 0x29 }, // VMware
		{ 0x00, 0x1C, 0x14 }, // VMware
		{ 0x00, 0x50, 0x56 }, // VMware
		{ 0x00, 0x16, 0x3E }, // Xen
		{ 0x52, 0x54, 0x00 }, // QEMU / KVM
		{ 0x00, 0x1C, 0x42 }, // Parallels
		{ 0xBC, 0x24, 0x11 }, // Proxmox
	};

	for (auto adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
		if (adapter->PhysicalAddressLength != 6) {
			continue;
		}

		// skip loopback/tunnel pseudo-adapters
		if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
			adapter->IfType == IF_TYPE_TUNNEL) {
			continue;
		}

		for (const auto& oui : known) {
			if (memcmp(adapter->PhysicalAddress, oui, 3) == 0) {
				return true;
			}
		}
	}

	return false;
}


namespace {

	// runs one WQL query against ROOT\CIMV2 and collects every returned
	// row's value for `property` as a wide string
	bool runWmiQuery(
		const wchar_t* wql, 
		const wchar_t* property, 
		std::vector<std::wstring>& out) {

		IWbemLocator* locator = nullptr;
		IWbemServices* services = nullptr;
		IEnumWbemClassObject* enumerator = nullptr;
		bool ok = false;

		// NOTE: COM must be initialized & uninitialized in caller
		HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, reinterpret_cast<LPVOID*>(&locator));
		if (FAILED(hr)) {
			return false;
		}

		// connect to ROOT/CIMV2 namespace
		hr = locator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr,
			nullptr, 0, nullptr, nullptr, &services);
		if (FAILED(hr)) {
			locator->Release();
			return false;
		}

		// impersonating user to acquire required rights
		hr = CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
			RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
		if (FAILED(hr)) {
			services->Release();
			locator->Release();
			return false;
		}

		// execute WQL-query
		hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);
		if (FAILED(hr)) {
			services->Release();
			locator->Release();
			return false;
		}

		// iterating through results

		IWbemClassObject* obj = nullptr;
		ULONG returned = 0;

		while (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK) {
			VARIANT vt;
			VariantInit(&vt);

			if (SUCCEEDED(obj->Get(property, 0, &vt, nullptr, nullptr))) {
				if (vt.vt == VT_BSTR && vt.bstrVal != nullptr) {
					out.emplace_back(vt.bstrVal);
				}
			}

			VariantClear(&vt);
			obj->Release();
			ok = true;
		}

		enumerator->Release();
		services->Release();
		locator->Release();

		return ok;
	}

} // namespace


// look for VM vendors' substrings in WMI query results
bool protect::vmWmiHardwareStrings() {
	HRESULT coInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	bool comInitialized = SUCCEEDED(coInit);

	struct Query {
		const wchar_t* wql;
		const wchar_t* property;
	};

	static constexpr Query queries[] = {
		{ L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer" },
		{ L"SELECT Model FROM Win32_ComputerSystem", L"Model" },
		{ L"SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer" },
		{ L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber" },
		{ L"SELECT Version FROM Win32_BIOS", L"Version" },
		{ L"SELECT Manufacturer FROM Win32_BaseBoard", L"Manufacturer" },
		{ L"SELECT Product FROM Win32_BaseBoard", L"Product" },
		{ L"SELECT Model FROM Win32_DiskDrive", L"Model" },
	};

	static constexpr std::wstring_view needles[] = {
		L"VMWARE", L"VBOX", L"VIRTUALBOX", L"VIRTUAL MACHINE", L"QEMU",
		L"XEN", L"KVM", L"PARALLELS", L"INNOTEK", L"BOCHS"
	};

	bool suspicious = false;

	for (const auto& q : queries) {
		std::vector<std::wstring> values;
		if (!runWmiQuery(q.wql, q.property, values)) {
			continue;
		}

		for (auto& v : values) {
			std::wstring upper = v;
			std::transform(upper.begin(), upper.end(), upper.begin(),
				[](wchar_t c) { return static_cast<wchar_t>(::towupper(c)); });

			for (auto n : needles) {
				if (upper.find(n) != std::wstring::npos) {
					suspicious = true;
					break;
				}
			}
			if (suspicious) {
				break;
			}
		}
		if (suspicious) {
			break;
		}
	}

	if (comInitialized) {
		CoUninitialize();
	}

	return suspicious;
}


// get combined mask of anti-VM measures
uint8_t protect::vmCombinedMask() {
	uint8_t mask = 0;
	volatile uint8_t smask = 0;	// not actually used, kept as fake checks >:3

	smask |= vmCpuidHypervisorBit() ? (1 << 0) : 0;
	mask |= vmMacAddressOui()		? (1 << 0) : 0;
	
	mask |= vmCpuidVendorString()	? (1 << 1) : 0;
	
	smask |= vmCpuidTimingAnomaly() ? (1 << 2) : 0;
	mask |= vmWmiHardwareStrings()	? (1 << 2) : 0;
	
	mask |= vmFirmwareTable()		? (1 << 3) : 0;
	
	return mask;
}


// CODE INTEGRITY	===========================================================

// crc-32 realization
uint32_t protect::crc32(const void* data, size_t len) {
	static const auto table = [] {
		std::array<uint32_t, 256> t{};
		for (uint32_t i = 0; i < 256; ++i) {
			uint32_t c = i;
			for (int k = 0; k < 8; ++k) {
				c = (c & 1) ? (CRC_CONSTANT ^ (c >> 1)) : (c >> 1);
			}
			t[i] = c;
		}
		return t;
		}();

	uint32_t crc = 0xFFFFFFFFu;
	auto bytes = static_cast<const uint8_t*>(data);
	for (size_t i = 0; i < len; ++i) {
		crc = table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
	}
	return crc ^ 0xFFFFFFFFu;
}


namespace {
	// INSERT CALIBRATE VALUE HERE
	constexpr uint32_t EXPECTED_PWDCHK_CRC = 0x8FAFEC31;
}	// namespace


// integrity check function
bool protect::integrityOk() {
	HMODULE base = GetModuleHandleW(nullptr);
	if (!base) {
		return false;
	}

	auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
	auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
		reinterpret_cast<const BYTE*>(base) + dos->e_lfanew);

	auto section = IMAGE_FIRST_SECTION(nt);

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
		if (memcmp(section->Name, ".pwdchk", 7) == 0) {
			const BYTE* start = reinterpret_cast<const BYTE*>(base) 
				+ section->VirtualAddress;
			uint32_t crc = protect::crc32(start, section->Misc.VirtualSize);

#ifdef PROTECT_CALIBRATE
			std::println(stderr, "[calibrate] .pwdchk crc32 = {:#010x}", crc);
			return true;
#else
			return crc == EXPECTED_PWDCHK_CRC;
#endif
		}
	}

	return false;	// section not found
					// treating this as a sign of tampering
}


// SELF-MODIFYING CODE	=======================================================

// runs protected function that XORs two args and returns result
int protect::runXorStub(int a, int b) {
	// original (decrypted) x64 machine code:
	//     8B C1         mov  eax, ecx
	//     33 C2         xor  eax, edx
	//     C3            ret
	// (the x64 calling convention passes the first two int arguments in
	// ecx/edx, so this short sequence implements exactly (a ^ b))

	static constexpr uint8_t XKEY = 0xA5;
	static constexpr uint8_t cipher[] = {
		uint8_t(0x8B ^ XKEY), uint8_t(0xC1 ^ XKEY),
		uint8_t(0x33 ^ XKEY), uint8_t(0xC2 ^ XKEY),
		uint8_t(0xC3 ^ XKEY),
	};

	uint8_t plain[sizeof(cipher)];
	for (size_t i = 0; i < sizeof(cipher); ++i) {
		plain[i] = static_cast<uint8_t>(cipher[i] ^ XKEY);
	}

	void* mem = VirtualAlloc(nullptr, sizeof(plain), 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mem) {
		SecureZeroMemory(plain, sizeof(plain));
		return ~(a ^ b); // deliberately "wrong" value -- environment looks suspicious
	}

	memcpy(mem, plain, sizeof(plain));
	SecureZeroMemory(plain, sizeof(plain));

	DWORD oldProtect{};
	if (!VirtualProtect(mem, sizeof(cipher), PAGE_EXECUTE_READ, &oldProtect)) {
		VirtualFree(mem, 0, MEM_RELEASE);
		return ~(a ^ b);
	}

	using StubFn = int(*)(int, int);
	auto fn = reinterpret_cast<StubFn>(mem);
	int result = fn(a, b);

	VirtualFree(mem, 0, MEM_RELEASE);
	return result;
}


// CONTROL FLOW OBFUSCATION VIA SEH	===========================================

uint8_t protect::sehGate(bool passwordMatches, uint8_t currentGuard) {
	uint8_t result = currentGuard;

	// both branches unconditionally raise an exception, 
	// so __except filter expression decides flow
	__try {
		if (!passwordMatches) {
			RaiseException(0xE0000001, 0, 0, nullptr);
		}
		RaiseException(0xE0000000, 0, 0, nullptr);
	}
	__except (
		(GetExceptionCode() == 0xE0000001 || GetExceptionCode() == 0xE0000000)
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH) {

		if (GetExceptionCode() == 0xE0000001) {
			result |= 0x80;
		}
	}

	return result;
}


// ASM ANTI-DISASM PRIMITIVES	===============================================

extern "C" int asmJunkByteTrick(int x);
extern "C" const uint8_t* asmCallOverDataTrick();


// returns x without changes
int protect::identityViaAsm(int x) {
	return asmJunkByteTrick(x);
}


// checks if asm tricks were tampered with
bool protect::asmObfuscationOk() {
	if (asmJunkByteTrick(0x37) != 0x37) {
		return false;
	}

	const uint8_t* data = asmCallOverDataTrick();

	char decoded[11]{};
	for (int i = 0; i < 10; ++i) {
		decoded[i] = static_cast<char>(data[i] ^ 0x55);
	}
	decoded[10] = '\0';

	std::string expected = PROTECT_XORSTR("PROTECTED");

	return memcmp(decoded, expected.c_str(), 10) == 0; // 9 chars + NUL
}


#ifdef DEBUG

// guard breakdown
void protect::debugPrintGuardBreakdown() {
	std::println(stderr, "[guard] adCombinedMask()      = {:#04x}  (expected 0x00)",
		adCombinedMask());

	std::println(stderr, "[guard] vmCombinedMask()      = {:#04x}  (expected 0x00)",
		vmCombinedMask());
	
	std::println(stderr, "[guard] integrityOk()         = {}", integrityOk());
	std::println(stderr, "[guard] runXorStub(0x5A,0xA5) = {:#04x}  (expected 0xff)",
		runXorStub(0x5A, 0xA5));
	
	std::println(stderr, "[guard] asmObfuscationOk()    = {}", asmObfuscationOk());
	std::println(stderr, "[guard] computeGuardByte()    = {:#04x}", computeGuardByte());
}

#endif


// FINAL GUARD BYTE	===========================================================

uint8_t protect::computeGuardByte() {
	uint8_t guard = 0;

	guard |= adCombinedMask();
	guard |= vmCombinedMask();

	if (!integrityOk()) {
		guard |= 0x01;
	}

	if (runXorStub(0x5A, 0xA5) != (0x5A ^ 0xA5)) {
		guard |= 0x02;
	}

	if (!asmObfuscationOk()) {
		guard |= 0x04;
	}

	return guard;
}
