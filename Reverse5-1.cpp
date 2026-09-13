/****************************************************************************** 
* 
*	Reverse5-1.cpp: application entry point
* 
*	C++23, CMake 3.20+
* 
*	|	crackme with file search tool as payload
* 
* 
* NOTES:
*	...
* 
* 
******************************************************************************/


#include "Reverse5-1.h"


[[nodiscard]] static ReturnCode outputResults(std::vector<SearchResult>);
[[nodiscard]] static ReturnCode \
	writeKey(std::filesystem::path, std::string);

[[nodiscard]] static std::expected<std::string, ReturnCode> \
	readPass(std::filesystem::path);

[[nodiscard]] static std::expected<std::string, ReturnCode> \
	convertKey(std::array<uint8_t, SERIAL_SIZE>);

[[nodiscard]] static std::expected<std::array<uint8_t, SERIAL_SIZE>, ReturnCode> \
	checkPassword(std::string);

[[nodiscard]] static std::expected<Task, ReturnCode> parseArgs(int, char**);
[[nodiscard]] static std::expected<std::vector<SearchResult>, ReturnCode> \
	needleSearch(Task);

static void usage();


inline constexpr auto PASSWORD = "Worker bees can leave. "
								"Even drones can fly away. "
								"The Queen is their slave.";


inline constexpr std::array<uint8_t, SERIAL_SIZE> KEY = {
	0xDE, 0xAD, 0xCA, 0xFE, 0x42
};


// Displays USAGE info for application
static void usage() {
	std::println("USAGE:");
	std::println("  crackme.exe <needle> <path...> [-r]");
	std::println();
	std::println("  needle       text to search for");
	std::println("  path         one or more files or directories to search");
	std::println("  -r           search directories recursively");
	std::println();
	std::println("A file named \"{}\" must exist next to the executable and", \
		PASSWORD_PATH);
	std::println("contain the unlock password.");
}


// Reads password from file located at *path*
static std::expected<std::string, ReturnCode> readPass(std::filesystem::path path) {
	std::error_code ec{};

	if (!std::filesystem::exists(path, ec) || ec) {
		std::println(stderr, "{}password file \"{}\" not found", \
			FAIL_MSG_PREFIX, path.string());
		return std::unexpected(ReturnCode::Failure);
	}

	std::ifstream file(path, std::ios::in | std::ios::binary);
	if (!file.is_open()) {
		std::println(stderr, "{}could not open password file", FAIL_MSG_PREFIX);
		return std::unexpected(ReturnCode::Failure);
	}

	// slurping password file
	std::stringstream buf{};
	buf << file.rdbuf();
	std::string pass = buf.str();

	// strip trailing whitespace / line endings
	while (!pass.empty() && (pass.back() == '\n' || \
		pass.back() == '\r' || pass.back() == ' ' || pass.back() == '\t')) {

		pass.pop_back();
	}

	if (pass.empty()) {
		std::println(stderr, "{}password file is empty", FAIL_MSG_PREFIX);
		return std::unexpected(ReturnCode::Failure);
	}

	return pass;
}


static std::expected<std::string, ReturnCode> \
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
static ReturnCode \
	writeKey(std::filesystem::path path, std::string key) {

	std::ofstream file(path, std::ios::out | std::ios::trunc);
	if (!file.is_open()) {
		std::println(stderr, "{}could not open \"{}\" for writing",
			FAIL_MSG_PREFIX, path.string());
		return ReturnCode::Failure;
	}

	file << SERIAL_PREFIX << key << SERIAL_SUFFIX;

	if (!file.good()) {
		std::println(stderr, "{}failed to write serial", FAIL_MSG_PREFIX);
		return ReturnCode::Failure;
	}

	return ReturnCode::Success;
}


// Checks if *pass* is correct
static std::expected<std::array<uint8_t, SERIAL_SIZE>, ReturnCode> \
	checkPassword(std::string pass) {

	if (pass != PASSWORD) {
		std::println(stderr, "{}incorrect password", FAIL_MSG_PREFIX);
		return std::unexpected(ReturnCode::Failure);
	}

	return KEY;
}


// Parses command line arguments
static std::expected<Task, ReturnCode> parseArgs(int ac, char** av) {
	if (ac < MIN_REQUIRED_ARGS) {
		std::println(stderr, "{}too few arguments", FAIL_MSG_PREFIX);
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
			std::println(stderr, "{}invalid argument", FAIL_MSG_PREFIX);
			usage();
			return std::unexpected(ReturnCode::Failure);
		}
	}

	if (res.needle.empty() || res.paths.empty()) {
		std::println(stderr, "{}missing search term or search path", FAIL_MSG_PREFIX);
		usage();
		return std::unexpected(ReturnCode::Failure);
	}

	return res;
}


// Performs search for keyword (needle) in files according to *task*
static std::expected<std::vector<SearchResult>, ReturnCode> \
	needleSearch(Task task) {

	std::vector<SearchResult> res{};
	
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
					.column = pos + 1
					});

				pos = line.find(task.needle, pos + 1);
			}

			++line_num;
		}
	}

	return res;
}


// Outputs search results to terminal
static ReturnCode outputResults(std::vector<SearchResult> results) {
	for (const auto& res : results) {
		std::println("{} at ({}, {})", res.path.string(), res.line, res.column);
	}

	std::println("{}{} entries found", DONE_MSG_PREFIX, results.size());

	return ReturnCode::Success;
}


// Entry point
int main(int argc, char* argv[])
{
	auto pass = readPass(PASSWORD_PATH);
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

	ReturnCode writeRes = writeKey(SERIAL_PATH, keyString.value());
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

	return EXIT_SUCCESS;
}
