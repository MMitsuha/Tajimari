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
EntryPoint_t OriginalEntryPoint = reinterpret_cast<EntryPoint_t>(0xCCCCCCCCCCCCCCCC);

extern "C"
__declspec(dllexport)
void
__fastcall
EntryPoint(
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
	//LI_FN(LoadLibraryW)(L"USER32.dll");
	//LI_FN(MessageBoxW)(nullptr, L"Hello World", L"Infected", MB_OK);

	/*ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	ZyanUSize offset = 0;
	const ZyanUSize length = -1;
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (uint8_t*)OriginalEntryPoint + offset, length - offset, &instruction)))
	{
		if (instruction.opcode == 0xc3 ||
			instruction.opcode == 0xcb ||
			instruction.opcode == 0xc2 ||
			instruction.opcode == 0xca)
			break;

		*((uint8_t*)OriginalEntryPoint + offset) = instruction.opcode ^ 2;

		offset += instruction.length;
	}*/

	OriginalEntryPoint();
	return;
}
