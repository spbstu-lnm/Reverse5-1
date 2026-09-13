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
