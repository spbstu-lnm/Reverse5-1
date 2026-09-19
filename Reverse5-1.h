/******************************************************************************
* 	
* 	Reverse5-1.h : application include file
* 
*	C++23, CMake 3.20+
* 
*	NOTES:
*		...
* 
******************************************************************************/


#pragma once


#include <print>		// used for std::println etc
#include <filesystem>	// used for fs::path etc
#include <span>			// used for std::span
#include <vector>		// used for std::vector
#include <string>		// used for std::string
#include <string_view>	// used for std::string_view
#include <ranges>		// used for std::views::drop
#include <expected>		// used for std::expected etc
#include <compare>		// used for operator<=> (sorting results)
#include <fstream>		// used for std::ifstream
#include <sstream>		// used for std::stringstream
#include <format>		// used for std::format

// WIN32_LEAN_AND_MEAN + NOMINMAX are defined in CMakeLists.txt
#include <Windows.h>	// SecureZeroMemory, Sleep, etc

#include "Protect.h"


// following string constants are protected
inline std::string PASSWORD_PATH() { return PROTECT_XORSTR("password.txt"); }
inline std::string SERIAL_PATH()   { return PROTECT_XORSTR("serial.txt"); }

inline std::string SERIAL_PREFIX() { return PROTECT_XORSTR("KEY$"); }
inline std::string SERIAL_SUFFIX() { return PROTECT_XORSTR("$"); }

// size of serial in bytes
inline constexpr auto SERIAL_SIZE = 5;

inline std::string FAIL_MSG_PREFIX() { return PROTECT_XORSTR("FAIL: "); }
inline std::string DONE_MSG_PREFIX() { return PROTECT_XORSTR("DONE: "); }

inline constexpr auto DROPPED_ARGS = 1;
inline constexpr auto MIN_REQUIRED_ARGS = 3;


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
