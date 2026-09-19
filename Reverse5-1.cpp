/****************************************************************************** 
* 
*	Reverse5-1.cpp: application entry point
* 
*	C++23, CMake 3.20+
* 
*	|	crackme with file search tool as payload
* 
* 
*	NOTES:
*		...
* 
* 
******************************************************************************/


#include "Reverse5-1.h"


// define DEBUG in CMakeLists.txt if needed


[[nodiscard]] static ReturnCode outputResults(std::vector<SearchResult>);
[[nodiscard]] static ReturnCode 
	writeKey(std::filesystem::path, std::string);

[[nodiscard]] static std::expected<std::string, ReturnCode> 
	readPass(std::filesystem::path);

[[nodiscard]] static std::expected<std::string, ReturnCode> 
	convertKey(std::array<uint8_t, SERIAL_SIZE>);

[[nodiscard]] static std::expected<std::array<uint8_t, SERIAL_SIZE>, ReturnCode> 
	checkPassword(std::string);

[[nodiscard]] static std::expected<Task, ReturnCode> parseArgs(int, char**);
[[nodiscard]] static std::expected<std::vector<SearchResult>, ReturnCode> 
	needleSearch(Task);

static void usage();


// std::println / std::format requires 
// format string to be a compile-time literal 
template <typename... Args>
static void printlnRuntime(std::FILE* stream, std::string_view fmt, Args&&... args) {
	std::string withNewline(fmt);
	withNewline += '\n';
	std::vprint_unicode(stream, withNewline, std::make_format_args(args...));
}

template <typename... Args>
static void printlnRuntime(std::string_view fmt, Args&&... args) {
	printlnRuntime(stdout, fmt, args...);
}


// protected string constants (decrypted at the point of use)

static std::string PASSWORD() {
	return PROTECT_XORSTR(
		"Worker bees can leave. Even drones can fly away. The Queen is their slave.");
}

static std::array<uint8_t, SERIAL_SIZE> KEY() {
	return PROTECT_XORBYTES(SERIAL_SIZE, 0xDE, 0xAD, 0xCA, 0xFE, 0x42);
}

// holds a copy of the password after it's been verified in checkPassword,
// for the independent re-check in needleSearch (see below); wiped right
// after use
static std::string g_verifiedPass;


// Displays USAGE info for application
static void usage() {
	std::println("{}", PROTECT_XORSTR("USAGE:"));
	std::println("{}", PROTECT_XORSTR("  crackme.exe <needle> <path...> [-r]"));
	std::println();
	std::println("{}", PROTECT_XORSTR("  needle       text to search for"));
	std::println("{}", PROTECT_XORSTR(
		"  path         one or more files or directories to search"));

	std::println("{}", PROTECT_XORSTR(
		"  -r           search directories recursively"));

	std::println();
	printlnRuntime(PROTECT_XORSTR(
		"A file named \"{}\" must exist next to the executable and"),
		PASSWORD_PATH());

	std::println("{}", PROTECT_XORSTR("contain the unlock password."));
}


// Reads password from file located at *path*
static std::expected<std::string, ReturnCode> readPass(std::filesystem::path path) {
	std::error_code ec{};

	if (!std::filesystem::exists(path, ec) || ec) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}password file \"{}\" not found"),
			FAIL_MSG_PREFIX(), path.string());

		return std::unexpected(ReturnCode::Failure);
	}

	std::ifstream file(path, std::ios::in | std::ios::binary);
	if (!file.is_open()) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}could not open password file"), 
			FAIL_MSG_PREFIX());

		return std::unexpected(ReturnCode::Failure);
	}

	// slurping password file
	std::stringstream buf{};
	buf << file.rdbuf();
	std::string pass = buf.str();

	// strip trailing whitespace / line endings
	while (!pass.empty() && (pass.back() == '\n' || 
		pass.back() == '\r' || pass.back() == ' ' || pass.back() == '\t')) {

		pass.pop_back();
	}

	if (pass.empty()) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}password file is empty"), 
			FAIL_MSG_PREFIX());

		return std::unexpected(ReturnCode::Failure);
	}

	// decoy password check
	volatile bool decoyMatch = (pass == PROTECT_XORSTR("robloxismylife"));
	if (decoyMatch) {
		Sleep(0);
	}

	return pass;
}


static std::expected<std::string, ReturnCode> 
	convertKey(std::array<uint8_t, SERIAL_SIZE> bytes) {

	std::string keyString;
	// allocating memory upfront for performance
	keyString.reserve(SERIAL_SIZE * 2);

	for (uint8_t byte : bytes) {
		keyString += std::format("{:02X}", byte);
	}

	return keyString;
}


// Writes *key* string to file located at *path*
static ReturnCode 
	writeKey(std::filesystem::path path, std::string key) {

	std::ofstream file(path, std::ios::out | std::ios::trunc);
	if (!file.is_open()) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}could not open \"{}\" for writing"),
			FAIL_MSG_PREFIX(), path.string());

		return ReturnCode::Failure;
	}

	// key will be corrupted if any checks are failed
	uint8_t guard = protect::computeGuardByte();
	if (guard != 0) {
		for (char& c : key) {
			c = static_cast<char>(c ^ (guard & 0x0F));
		}
	}

	file << SERIAL_PREFIX() << key << SERIAL_SUFFIX();

	if (!file.good()) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}failed to write serial"), 
			FAIL_MSG_PREFIX());

		return ReturnCode::Failure;
	}

	return ReturnCode::Success;
}


// Checks if *pass* is correct
// integrity protected with CRC-32 by protect::integrityOk()
#pragma section(".pwdchk", execute, read)
#pragma code_seg(push, r1, ".pwdchk")

static std::expected<std::array<uint8_t, SERIAL_SIZE>, ReturnCode> 
	checkPassword(std::string pass) {

	bool matches = (pass == PASSWORD());

	uint8_t guard = protect::computeGuardByte();
	guard = protect::sehGate(matches, guard);

	if (!matches) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}incorrect password"), 
			FAIL_MSG_PREFIX());

		return std::unexpected(ReturnCode::Failure);
	}

	// stashing password copy in global variable for re-check later
	g_verifiedPass = pass;

	std::array<uint8_t, SERIAL_SIZE> key = KEY();

	// guard is mixed into the key bytes: 
	// if any checks failed --> key will be corrupted
	for (uint8_t& byte : key) {
		int xored = protect::runXorStub(byte, guard);
		byte = static_cast<uint8_t>(protect::identityViaAsm(xored));
	}

	return key;
}

#pragma code_seg(pop, r1)


// Parses command line arguments
static std::expected<Task, ReturnCode> parseArgs(int ac, char** av) {
	if (ac < MIN_REQUIRED_ARGS) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}too few arguments"), 
			FAIL_MSG_PREFIX());

		usage();
		return std::unexpected(ReturnCode::Failure);
	}

	Task res{};

	auto args = std::span(av, ac) | std::views::drop(DROPPED_ARGS);
	
	for (auto [idx, arg] : std::views::enumerate(args)) {
		std::string_view astring = std::string_view(arg);
		std::error_code ec{};

		if (astring == "-r") {
			res.is_recursive = true;
		}
		else if (std::filesystem::exists(astring, ec)) {
			res.paths.emplace_back(astring);
		}
		else if (res.needle.empty()) {
			res.needle = astring;
		}
		else {
			printlnRuntime(stderr, PROTECT_XORSTR("{}invalid argument"), 
				FAIL_MSG_PREFIX());

			usage();
			return std::unexpected(ReturnCode::Failure);
		}
	}

	if (res.needle.empty() || res.paths.empty()) {
		printlnRuntime(stderr, PROTECT_XORSTR("{}missing search term or search path"), 
			FAIL_MSG_PREFIX());

		usage();
		return std::unexpected(ReturnCode::Failure);
	}

	return res;
}


// Performs search for keyword (needle) in files according to *task*
static std::expected<std::vector<SearchResult>, ReturnCode> 
	needleSearch(Task task) {

	std::vector<SearchResult> res{};
	
	// re-check of stashed password
	uint8_t guard = protect::computeGuardByte();
	bool stillVerified = !g_verifiedPass.empty() && (g_verifiedPass == PASSWORD());
	if (!stillVerified) {
		guard |= 0x04;
	}

	std::vector<std::filesystem::path> files{};
	std::error_code ec{};

	for (const auto& p : task.paths) {
		if (std::filesystem::is_directory(p, ec)) {
			if (task.is_recursive) {
				for (const auto& entry :
					std::filesystem::recursive_directory_iterator(p, ec)) {

					if (entry.is_regular_file(ec)) {
						files.push_back(entry.path());
					}
				}
			}
			else {
				for (const auto& entry :
					std::filesystem::directory_iterator(p, ec)) {

					if (entry.is_regular_file(ec)) {
						files.push_back(entry.path());
					}
				}
			}
		}
		else if (std::filesystem::is_regular_file(p, ec)) {
			files.push_back(p);
		}
	}

	for (const auto& file : files) {
		std::ifstream in(file, std::ios::in);
		if (!in.is_open()) {
			continue;
		}

		std::string line{};
		size_t line_num = 1;

		while (std::getline(in, line)) {
			size_t pos = line.find(task.needle);

			while (pos != std::string::npos) {
				res.push_back(SearchResult{
					.path = file,
					.line = line_num,

					// anti-disasm + incorrect result if guard is non-zero
					.column = pos + protect::identityViaAsm(1) + guard
					});

				pos = line.find(task.needle, pos + 1);
			}

			++line_num;
		}
	}

	// securely wipe password copy from memory
	if (!g_verifiedPass.empty()) {
		SecureZeroMemory(g_verifiedPass.data(), g_verifiedPass.size());
		g_verifiedPass.clear();
	}

	return res;
}


// Outputs search results to terminal
static ReturnCode outputResults(std::vector<SearchResult> results) {
	for (const auto& res : results) {
		printlnRuntime(PROTECT_XORSTR("{} at ({}, {})"), 
			res.path.string(), res.line, res.column);
	}

	printlnRuntime(PROTECT_XORSTR("{}{} entries found"), 
		DONE_MSG_PREFIX(), results.size());

	return ReturnCode::Success;
}


// Entry point
int main(int argc, char* argv[])
{
	auto pass = readPass(PASSWORD_PATH());
	if (!pass) {
		return EXIT_FAILURE;
	}

	auto key = checkPassword(pass.value());
	if (!key) {
		return EXIT_FAILURE;
	}

	auto keyString = convertKey(key.value());
	if (!keyString) {
		return EXIT_FAILURE;
	}

	ReturnCode writeRes = writeKey(SERIAL_PATH(), keyString.value());
	if (writeRes != ReturnCode::Success) {
		return EXIT_FAILURE;
	}

	auto task = parseArgs(argc, argv);
	if (!task) {
		return EXIT_FAILURE;
	}

	auto searchRes = needleSearch(task.value());
	if (!searchRes) {
		return EXIT_FAILURE;
	}

	ReturnCode outputRes = outputResults(searchRes.value());
	if (outputRes != ReturnCode::Success) {
		return EXIT_FAILURE;
	}

#ifdef DEBUG
	protect::debugPrintGuardBreakdown();
#endif

	return EXIT_SUCCESS;
}
