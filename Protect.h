/******************************************************************************
* 
*	Protect.h : anti-reverse protection tools header file
* 
*	C++23, CMake 3.20+
* 
*	NOTES:
*		...
* 
******************************************************************************/


#pragma once


// define PROTECT_CALIBRATE in CMakeLists.txt if needed


#include <cstdint>
#include <cstddef>
#include <string>
#include <array>

// WIN32_LEAN_AND_MEAN + NOMINMAX are defined in CMakeLists.txt
#include <Windows.h>


inline constexpr auto KNUTH_CONSTANT = 0x9E3779B9u;
inline constexpr auto OTHER_CONSTANT = 0x85EBCA6Bu;
inline constexpr auto PRIME_NUMBER = 97u;
inline constexpr auto SHIFT_NUMBER = 3;

// reversed polynomial mask for CRC-32 (acc. to IEEE 802.3)
inline constexpr auto CRC_CONSTANT = 0xEDB88320u;


namespace protect::internal {

	// compile-time encryption for strings
	// decrypted in runtime right before use
	// buffer zeroed immediately after use
	template <size_t N>
	struct XorStr {
		char cipher[N]{};

		constexpr XorStr(const char(&plain)[N], uint32_t seed) {
			for (size_t i = 0; i < N; ++i) {
				uint8_t k = static_cast<uint8_t> \
					((seed * KNUTH_CONSTANT + i * PRIME_NUMBER) >> SHIFT_NUMBER);

				cipher[i] = static_cast<char>(static_cast<uint8_t>(plain[i]) ^ k);
			}
		}

		void decrypt(char* out, uint32_t seed) const {
			for (size_t i = 0; i < N; ++i) {
				uint8_t k = static_cast<uint8_t> \
					((seed * KNUTH_CONSTANT + i * PRIME_NUMBER) >> SHIFT_NUMBER);

				out[i] = static_cast<char>(static_cast<uint8_t>(cipher[i]) ^ k);
			}
		}
	};

	// RAII wrapper: zeroes out protected data buffer
	struct WipeGuard {
		char* buf;
		size_t len;
		~WipeGuard() { SecureZeroMemory(buf, len); }
	};

	// compile-time encryption for bytes
	// same idea as XorStr
	template <size_t N>
	struct XorBytes {
		uint8_t cipher[N]{};

		constexpr XorBytes(const uint8_t(&plain)[N], uint32_t seed) {
			for (size_t i = 0; i < N; ++i) {
				uint8_t k = static_cast<uint8_t> \
					((seed * KNUTH_CONSTANT + i * PRIME_NUMBER) >> SHIFT_NUMBER);

				cipher[i] = static_cast<uint8_t>(plain[i] ^ k);
			}
		}

		void decrypt(uint8_t* out, uint32_t seed) const {
			for (size_t i = 0; i < N; ++i) {
				uint8_t k = static_cast<uint8_t> \
					((seed * KNUTH_CONSTANT + i * PRIME_NUMBER) >> SHIFT_NUMBER);

				out[i] = static_cast<uint8_t>(cipher[i] ^ k);
			}
		}
	};

}	// namespace protect::detail


#define PROTECT_XORSTR(str)											\
	[]() -> std::string {											\
		static constexpr auto _enc =								\
			protect::internal::XorStr<sizeof(str)>					\
				(str, __COUNTER__ + KNUTH_CONSTANT);				\
		char _buf[sizeof(str)];										\
		_enc.decrypt(_buf, __COUNTER__ - 1 + KNUTH_CONSTANT);		\
		protect::internal::WipeGuard _wipe{ _buf, sizeof(_buf) };	\
		return std::string(_buf, sizeof(_buf) - 1);					\
	}()

#define PROTECT_XORBYTES(N, ...)										\
	[]() -> std::array<uint8_t, N> {									\
		static constexpr uint8_t _plain[N] = { __VA_ARGS__ };			\
		static constexpr auto _enc = protect::internal::XorBytes<N>		\
			(_plain, __COUNTER__ + OTHER_CONSTANT);						\
		std::array<uint8_t, N> _out{};									\
		_enc.decrypt(_out.data(), __COUNTER__ - 1 + OTHER_CONSTANT);	\
		return _out;													\
	}()


namespace protect {

	// ==== anti-debug
	bool adIsDebuggerPresent();
	bool adPebFlag();
	bool adNtQueryDebugPort();
	bool adHardwareBreakpoints();
	bool adTimingAnomaly();

	// bitmask of ad checks; should be zero
	uint8_t adCombinedMask();


	// ==== anti-vm
	bool vmCpuidHypervisorBit();	// produces false-positives
	bool vmCpuidVendorString();
	bool vmCpuidTimingAnomaly();	// produces false-positives
	bool vmFirmwareTable();

	bool vmMacAddressOui();
	bool vmWmiHardwareStrings();

	// bitmask of vm checks; should be zero
	uint8_t vmCombinedMask();


	// ==== code integrity (CRC32 of PE section for checkPassword)
	uint32_t crc32(const void* data, size_t len);

	// [ REQUIRES CALIBRATION ]
	// yields true if .pwdchk section matches EXPECTED_PWDCHK_CRC
	bool integrityOk();


	// ==== self-modifying code
	int runXorStub(int a, int b);


	// ==== control flow obfuscation via SEH exceptions
	uint8_t sehGate(bool passwordMatches, uint8_t currentGuard);


	// ==== asm anti-disassembly primitives
	int identityViaAsm(int x);

	bool asmObfuscationOk();


	// DEBUG ONLY: prints failed checks
	void debugPrintGuardBreakdown();

	// ==== final guard byte
	// equals zero if all checks are passed
	uint8_t computeGuardByte();

}	// namespace protect
