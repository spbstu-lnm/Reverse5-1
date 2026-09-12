/******************************************************************************
* 	
* 	Reverse5-1.h : include file
* 
******************************************************************************/


#pragma once


#include <print>
#include <filesystem>
#include <span>
#include <vector>
#include <string_view>
#include <ranges>
#include <expected>
#include <compare>

#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")


inline constexpr auto PASSWORD_PATH = "password.txt";
inline constexpr auto SERIAL_PATH = "serial.txt";

inline constexpr auto SERIAL_PREFIX = "KEY$";
inline constexpr auto SERIAL_SUFFIX = "$";
inline constexpr auto SERIAL_LENGTH = 10;

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
