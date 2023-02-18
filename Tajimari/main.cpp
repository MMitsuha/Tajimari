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
	//std::string pathTarget = R"(C:\Windows\system32\notepad.exe)";
	std::string pathTemplate = R"(.\ShellcodeTemplate.dll)";
	//std::string pathTarget = R"(E:\upx\upx.exe)";
	std::string pathTarget = R"(.\TestTarget.exe)";
	//std::string pathTarget = R"(E:\dllexp-x64\dllexp.exe)";
	PeMaster::Pe objTemplate(pathTemplate);
	PeMaster::Pe objTarget(pathTarget);

	auto checksum = objTarget.computeChecksum();
	spdlog::debug("Target checksum: 0x{:x}", checksum);

	auto imports = objTarget.enumImport();
	objTarget.setImport(imports);

	/*
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
	objTarget.updateHeaders();

	auto vaOriginalMain = objTarget.getNtHeaders().getOptionalHeader().ImageBase + objTarget.getNtHeaders().getOptionalHeader().AddressOfEntryPoint;
	auto rvaNewMain = secAdded.VirtualAddress + offsetMain;
	objTarget.getNtHeaders().getOptionalHeader().AddressOfEntryPoint = rvaNewMain;
	(*(uintptr_t*)(secAdded.m_content.data() + offsetVar)) = vaOriginalMain;
	*/

	objTarget.rebuild();
	objTarget.write(R"(.\Modified.exe)");

	STARTUPINFOW si{};
	PROCESS_INFORMATION pi{};
	si.cb = sizeof(si);
	WCHAR target[] = LR"(.\Modified.exe)";
	if (CreateProcessW(nullptr, target, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	return 0;
}
