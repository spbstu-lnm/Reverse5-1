/****************************************************************************** 
* 
*	Reverse5-1.cpp: application entry point
* 
*	C++23, CMake 3.20+
* 
*	|	crackme with file search tool as payload
* 
* 
* 
* NOTES:
*	- key is derived with PBKDF2 + SHA-256
* 
* 
******************************************************************************/


#include "Reverse5-1.h"


[[nodiscard]] static ReturnCode outputResults(std::vector<SearchResult>);
[[nodiscard]] static ReturnCode \
	writeKey(std::filesystem::path, std::array<uint8_t, SERIAL_LENGTH>);

[[nodiscard]] static std::expected<std::string, ReturnCode> \
	readPass(std::filesystem::path);

[[nodiscard]] static std::expected<std::array<uint8_t, SERIAL_LENGTH>, ReturnCode> \
	checkPassword(std::string);

[[nodiscard]] static std::expected<Task, ReturnCode> parseArgs(int, char**);
[[nodiscard]] static std::expected<std::vector<SearchResult>, ReturnCode> \
	needleSearch(Task);

static void usage();


// Displays USAGE info for application
static void usage() {
	// TODO: display USAGE
}


// Reads password from file located at *path*
static std::expected<std::string, ReturnCode> readPass(std::filesystem::path path) {
	// TODO: read password from file
}


// Writes *key* to file located at *path*
static ReturnCode \
	writeKey(std::filesystem::path path, std::array<uint8_t, SERIAL_LENGTH> key) {

	// TODO: write key to file
}


// Checks if *pass* is correct, derives key from *pass*
static std::expected<std::array<uint8_t, SERIAL_LENGTH>, ReturnCode> \
	checkPassword(std::string pass) {

	// TODO: check password, derive key
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
}


// Performs search for keyword (needle) in files according to *task*
static std::expected<std::vector<SearchResult>, ReturnCode> \
	needleSearch(Task task) {

	std::vector<SearchResult> res{};
	
	// TODO: search for keyword

	return res;
}


// Outputs search results to terminal
static ReturnCode outputResults(std::vector<SearchResult> results) {
	for (const auto& res : results) {
		std::println("{} at ({},{})", res.path, res.line, res.column);
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

	ReturnCode writeRes = writeKey(SERIAL_PATH, key.value());
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
