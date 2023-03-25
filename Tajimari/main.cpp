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

	uint64_t sizeOfCode = 0;

	for (auto& sec : objTarget.get_image_sections()) {
		if (sec.get_virtual_address() <= objTarget.get_ep() && objTarget.get_ep() <= sec.get_virtual_size()) {
			sizeOfCode = sec.get_virtual_size();
		}
	}

	uint32_t offsetMain = 0;
	uint32_t offsetEp = 0;
	uint32_t offsetSize = 0;

	for (auto& exp : get_exported_functions(objTemplate)) {
		if (exp.get_name() == "main") {
			offsetMain = exp.get_rva();
		}
		else if (exp.get_name() == "ep") {
			offsetEp = exp.get_rva();
		}
		else if (exp.get_name() == "sizeOfCode") {
			offsetSize = exp.get_rva();
		}

		if (offsetMain && offsetEp && offsetSize) break;
	}

	for (auto& sec : objTemplate.get_image_sections()) {
		if (sec.get_name() == ".text") {
			offsetMain -= sec.get_virtual_address();
			spdlog::info("Found main at offset: 0x{:x}", offsetMain);

			offsetEp -= sec.get_virtual_address();
			spdlog::info("Found var at offset: 0x{:x}", offsetEp);

			pe_bliss::section secTemp;
			secTemp.readable(true).writeable(true).executable(true);
			secTemp.set_name(".hack");
			secTemp.set_raw_data(sec.get_raw_data());
			auto& added = objTarget.add_section(secTemp);

			auto vaOriginalMain = objTarget.get_image_base_64() + objTarget.get_ep();
			auto rvaNewMain = added.get_virtual_address() + offsetMain;
			auto& raw_data = added.get_raw_data();
			(*(uintptr_t*)(raw_data.data() + offsetEp)) = vaOriginalMain;
			objTarget.set_ep(rvaNewMain);

			(*(uint64_t*)(raw_data.data() + offsetSize)) = sizeOfCode;

			break;
		}
	}

	std::vector<std::string> orderLib;
	std::vector<uint32_t> orderFunc;
	uint32_t order;

	std::map<std::string, std::map<uint32_t, std::tuple<std::string, uint64_t, uint16_t>>> rawImports;
	for (auto& lib : get_imported_functions(objTemplate)) {
		if (std::find(orderLib.cbegin(), orderLib.cend(), lib.get_name()) == orderLib.cend()) {
			orderLib.emplace_back(lib.get_name());
		}

		auto& data = rawImports[lib.get_name()];
		order = 0;

		for (auto& imp : lib.get_imported_functions()) {
			if (imp.has_name()) {
				data[order] = std::make_tuple(imp.get_name(), imp.get_iat_va(), 0);
			}
			else {
				data[order] = std::make_tuple(std::string(), imp.get_iat_va(), imp.get_ordinal());
			}

			++order;
		}
	}
	for (auto& lib : get_imported_functions(objTarget)) {
		if (std::find(orderLib.cbegin(), orderLib.cend(), lib.get_name()) == orderLib.cend()) {
			orderLib.emplace_back(lib.get_name());
		}

		auto& data = rawImports[lib.get_name()];
		order = 0;

		for (auto& imp : lib.get_imported_functions()) {
			if (imp.has_name()) {
				data[order] = std::make_tuple(imp.get_name(), imp.get_iat_va(), 0);
			}
			else {
				data[order] = std::make_tuple(std::string(), imp.get_iat_va(), imp.get_ordinal());
			}

			++order;
		}
	}

	pe_bliss::imported_functions_list newImports;
	for (auto& name : orderLib) {
		auto& funcs = rawImports[name];
		pe_bliss::import_library newLib;
		newLib.set_name(name);

		for (order = 0; order < funcs.size(); ++order) {
			auto& func = funcs[order];
			auto& name = std::get<0>(func);
			auto& va = std::get<1>(func);
			auto& ordinal = std::get<2>(func);
			pe_bliss::imported_function newFunc;
			newFunc.set_iat_va(va);

			if (name.empty()) {
				newFunc.set_ordinal(ordinal);
			}
			else {
				newFunc.set_name(name);
			}

			newLib.add_import(newFunc);
		}

		newImports.push_back(newLib);
	}

	pe_bliss::section impSection;
	impSection.get_raw_data().resize(1);
	impSection.set_name("newImp");
	impSection.readable(true).writeable(true);
	pe_bliss::section& attachedSection = objTarget.add_section(impSection);

	//pe_bliss::rebuild_imports(objTarget, newImports, attachedSection, pe_bliss::import_rebuilder_settings(true, false));

	// Create a new PE file
	std::ofstream fileNew(R"(.\Modified.exe)", std::ios::out | std::ios::binary | std::ios::trunc);

	// Rebuild PE file
	pe_bliss::rebuild_pe(objTarget, fileNew);
	fileNew.close();

	STARTUPINFOW si{};
	PROCESS_INFORMATION pi{};
	si.cb = sizeof(si);
	WCHAR target[] = LR"(.\Modified.exe)";
	if (CreateProcessW(nullptr, target, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		spdlog::error("Error starting Modified.exe, error code: {}", GetLastError());
	}

	return 0;
}
