#include "ExportTable.h"

namespace PeMaster {
	ExportTable::ExportTable(
		Pe& pe
	)
	{
		auto importDir = pe.getNtHeaders().getOptionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		auto rva = importDir.VirtualAddress;
		auto size = importDir.Size;

		if (rva == 0) {
			return;
		}

		auto base = pe.getBuffer().data();
		auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + pe.rvaToFo(rva));
		auto tableName = reinterpret_cast<uint32_t*>(base + pe.rvaToFo(pExport->AddressOfNames));
		auto tableAddr = reinterpret_cast<uint32_t*>(base + pe.rvaToFo(pExport->AddressOfFunctions));
		auto tableOrdName = reinterpret_cast<uint16_t*>(base + pe.rvaToFo(pExport->AddressOfNameOrdinals));
		auto baseOrdinal = pExport->Base;

		for (size_t i = 0; i < pExport->NumberOfFunctions; i++) {
			std::string funcName = reinterpret_cast<char*>(base + pe.rvaToFo(tableName[i]));
			auto funcOrd = tableOrdName[i] + baseOrdinal;
			auto funcRvaAddr = tableAddr[i];
			m_Table.emplace_back(funcOrd, funcName, funcRvaAddr);

			spdlog::debug("Ordinal: {}, name: {}, rva: 0x{:x}.", funcOrd, funcName, funcRvaAddr);
		}
	}
}
