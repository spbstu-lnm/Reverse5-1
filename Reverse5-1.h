/******************************************************************************
* 	
* 	Reverse5-1.h : include file
* 
******************************************************************************/


#pragma once


#include <print>		// used for std::println etc
#include <filesystem>	// used for fs::path etc
#include <span>			// used for std::span
#include <vector>		// used for std::vector
#include <string_view>	// used for std::string_view
#include <ranges>		// used for std::views::drop
#include <expected>		// used for std::expected etc
#include <compare>		// used for operator<=> (sorting results)
#include <fstream>		// used for std::ifstream

#include <Windows.h>	// required by bcrypt.h
#include <bcrypt.h>		// used for PBKDF2 + SHA-256
#pragma comment(lib, "bcrypt.lib")


inline constexpr auto PASSWORD_PATH = "password.txt";
inline constexpr auto SERIAL_PATH = "serial.txt";

inline constexpr auto SERIAL_PREFIX = "KEY$";
inline constexpr auto SERIAL_SUFFIX = "$";
// size of serial in bytes
inline constexpr auto SERIAL_SIZE = 5;

inline constexpr auto FAIL_MSG_PREFIX = "FAIL: ";
inline constexpr auto DONE_MSG_PREFIX = "DONE: ";

inline constexpr auto DROPPED_ARGS = 1;
inline constexpr auto MIN_REQUIRED_ARGS = 3;

inline constexpr auto PBKDF2_ITERATIONS = 100'000;
inline constexpr auto SALT_LENGTH = 16;
inline constexpr auto HASH_LENGTH = 32;

// 76 a2 b6 45 77 ec 66 1a 
// d4 72 16 27 7d c1 16 69
inline constexpr std::array<uint8_t, SALT_LENGTH> PBKDF2_SALT_VERIFY = {
	0x76, 0xA2, 0xB6, 0x45, 0x77, 0xEC, 0x66, 0x1A,
	0xD4, 0x72, 0x16, 0x27, 0x7D, 0xC1, 0x16, 0x69
};

// 23 fb 8c 13 e1 88 3c 6c 
// 8b 3f f1 6f 67 ce 95 59
inline constexpr std::array<uint8_t, SALT_LENGTH> PBKDF2_SALT_KEY = {
	0x23, 0xFB, 0x8C, 0x13, 0xE1, 0x88, 0x3C, 0x6C,
	0x8B, 0x3F, 0xF1, 0x6F, 0x67, 0xCE, 0x95, 0x59
};

inline constexpr std::array<uint8_t, HASH_LENGTH> EXPECTED_PASS_HASH = {
	// TODO: fill with actual values
	0x23, 0xFB, 0x8C, 0x13, 0xE1, 0x88, 0x3C, 0x6C,
	0x8B, 0x3F, 0xF1, 0x6F, 0x67, 0xCE, 0x95, 0x59,
	0x23, 0xFB, 0x8C, 0x13, 0xE1, 0x88, 0x3C, 0x6C,
	0x8B, 0x3F, 0xF1, 0x6F, 0x67, 0xCE, 0x95, 0x59
};


enum class ReturnCode {
	Success,
	Failure,
};


struct Task {
	std::vector<std::filesystem::path> paths;
	std::string needle;

	bool is_recursive = false;
};

struct SearchResult {
	std::filesystem::path path;
	size_t line = 0;
	size_t column = 0;

	auto operator<=>(const SearchResult&) const = default;
};
