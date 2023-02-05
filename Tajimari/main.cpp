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
	std::string pathTarget = R"(E:\upx\upx.exe)";
	PeMaster::Pe objTarget(pathTarget);

	objTarget.enumImport();
	objTarget.enumExport();
	objTarget.rebuild();

	objTarget.write(R"(.\qwq.exe)");

	return 0;
}
