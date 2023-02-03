#include "PeMaster.h"
#include <fstream>
#include <tuple>
#include <spdlog/spdlog.h>

namespace PeMaster {
	Pe::Pe(
		const std::filesystem::path& path
	) :BaseObject(path)
	{
		spdlog::debug("Pe constructed.");
		auto pDosHeader = getDosHeader();

		// Initialize dos stub
		std::copy(this->m_buffer.cbegin() + sizeof(IMAGE_DOS_HEADER),
			this->m_buffer.cbegin() + pDosHeader->e_lfanew,
			std::back_inserter(m_DosStub));

		// Initialize nt headers
		auto pNtHeaders = getNtHeaders();
		pNtHeaders->NtHeaders::open(pDosHeader->e_lfanew);

		// Initialize section headers
		m_SectionHeaders.resize(pNtHeaders->getFileHeader()->NumberOfSections);
		for (size_t i = 0; i < pNtHeaders->getFileHeader()->NumberOfSections; i++) {
			m_SectionHeaders[i].SectionHeader::open(m_buffer, pDosHeader->e_lfanew // At the beginning of nt headers
				+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNtHeaders->getFileHeader()->SizeOfOptionalHeader // At the beginning of section headers
				+ i * sizeof(IMAGE_SECTION_HEADER));
		}
	}

	bool
		Pe::open(
			const std::filesystem::path& path
		)
	{
		spdlog::debug("Building pe with given path.");
		// Initialize base object
		auto pBaseObject = asBaseObject();
		auto ret = pBaseObject->BaseObject::open(path);

		// Initialize dos header
		auto pDosHeader = getDosHeader();
		pDosHeader->DosHeader::open();

		// Initialize dos stub
		std::copy(this->m_buffer.cbegin() + sizeof(IMAGE_DOS_HEADER),
			this->m_buffer.cbegin() + pDosHeader->e_lfanew,
			std::back_inserter(m_DosStub));

		// Initialize nt headers
		auto pNtHeaders = getNtHeaders();
		pNtHeaders->NtHeaders::open(pDosHeader->e_lfanew);

		// Initialize section headers
		m_SectionHeaders.resize(pNtHeaders->getFileHeader()->NumberOfSections);
		for (size_t i = 0; i < pNtHeaders->getFileHeader()->NumberOfSections; i++) {
			m_SectionHeaders[i].SectionHeader::open(m_buffer, pDosHeader->e_lfanew // At the beginning of nt headers
				+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNtHeaders->getFileHeader()->SizeOfOptionalHeader // At the beginning of section headers
				+ i * sizeof(IMAGE_SECTION_HEADER));
		}

		return ret;
	}

	void
		Pe::open(
			const std::vector<uint8_t>& buffer
		)
	{
		spdlog::debug("Building pe with given buffer.");
		// Initialize base object
		auto pBaseObject = asBaseObject();
		pBaseObject->BaseObject::open(buffer);

		// Initialize dos header
		auto pDosHeader = getDosHeader();
		pDosHeader->DosHeader::open();

		// Initialize dos stub
		std::copy(this->m_buffer.cbegin() + sizeof(IMAGE_DOS_HEADER),
			this->m_buffer.cbegin() + pDosHeader->e_lfanew,
			std::back_inserter(m_DosStub));

		// Initialize nt headers
		auto pNtHeaders = getNtHeaders();
		pNtHeaders->NtHeaders::open(pDosHeader->e_lfanew);

		// Initialize section headers
		m_SectionHeaders.resize(pNtHeaders->getFileHeader()->NumberOfSections);
		for (size_t i = 0; i < pNtHeaders->getFileHeader()->NumberOfSections; i++) {
			m_SectionHeaders[i].SectionHeader::open(m_buffer, pDosHeader->e_lfanew // At the beginning of nt headers
				+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNtHeaders->getFileHeader()->SizeOfOptionalHeader // At the beginning of section headers
				+ i * sizeof(IMAGE_SECTION_HEADER));
		}
	}

	bool
		Pe::isValid(
			void
		)
	{
		return m_valid;
	}

	DosHeader*
		Pe::getDosHeader(
			void
		)
	{
		return dynamic_cast<DosHeader*>(this);
	}

	NtHeaders*
		Pe::getNtHeaders(
			void
		)
	{
		return dynamic_cast<NtHeaders*>(this);
	}

	std::vector<SectionHeader>*
		Pe::getSectionHeaders(
			void
		)
	{
		return &m_SectionHeaders;
	}

	BaseObject*
		Pe::asBaseObject(
			void
		)
	{
		return dynamic_cast<BaseObject*>(this);
	}

	SectionHeader
		Pe::getSectionByVa(
			uint64_t va
		)
	{
		auto rva = vaToRva(va);

		return getSectionByRva(rva);
	}

	SectionHeader
		Pe::getSectionByRva(
			uint64_t rva
		)
	{
		for (const auto& sec : m_SectionHeaders) {
			if (rva == std::clamp(rva, static_cast<uint64_t>(sec.VirtualAddress),
				static_cast<uint64_t>(sec.VirtualAddress + sec.Misc.VirtualSize))) return sec;
		}

		return {};
	}

	SectionHeader
		Pe::getSectionByFo(
			uint64_t fo
		)
	{
		for (const auto& sec : m_SectionHeaders) {
			if (fo == std::clamp(fo, static_cast<uint64_t>(sec.PointerToRawData),
				static_cast<uint64_t>(sec.PointerToRawData + sec.SizeOfRawData))) return sec;
		}

		return {};
	}

	//
	//	Pe read: enumerate data dictionary
	//

	std::vector<std::tuple<uint16_t, std::string, void*>>
		Pe::enumExport(
			void
		)
	{
		std::vector<std::tuple<uint16_t, std::string, void*>> ret;
		auto importDir = getNtHeaders()->getOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		auto rva = importDir.VirtualAddress;
		auto size = importDir.Size;

		if (rva == 0) {
			return {};
		}

		auto base = m_buffer.data();
		auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + rvaToFo(rva));
		auto tableName = reinterpret_cast<uint32_t*>(base + rvaToFo(pExport->AddressOfNames));
		auto tableAddr = reinterpret_cast<uint32_t*>(base + rvaToFo(pExport->AddressOfFunctions));
		auto tableOrdName = reinterpret_cast<uint16_t*>(base + rvaToFo(pExport->AddressOfNameOrdinals));
		auto baseOrdinal = pExport->Base;

		for (size_t i = 0; i < pExport->NumberOfFunctions; i++) {
			std::string funcName = reinterpret_cast<char*>(base + tableName[i]);
			auto funcOrd = tableOrdName[i] + baseOrdinal;
			void* funcAddr = base + tableAddr[funcOrd];
			ret.emplace_back(funcOrd, funcName, funcAddr);

			spdlog::debug("Ordinal: {}, name: {}, address: {}.", funcOrd, funcName, funcAddr);
		}

		return ret;
	}

	std::vector<std::pair<std::string, std::vector<std::tuple<IMAGE_THUNK_DATA, std::string, WORD>>>>
		Pe::enumImport(
			void
		)
	{
		std::vector<std::pair<std::string, std::vector<std::tuple<IMAGE_THUNK_DATA, std::string, WORD>>>> ret;
		auto importDir = getNtHeaders()->getOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto rva = importDir.VirtualAddress;
		auto size = importDir.Size;

		if (rva == 0) {
			return {};
		}

		auto base = m_buffer.data();
		auto pImport = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + rvaToFo(rva));

		while (pImport->Name) {
			std::vector<std::tuple<IMAGE_THUNK_DATA, std::string, WORD>> data;
			std::string name = reinterpret_cast<char*>(base + rvaToFo(pImport->Name));
			auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + rvaToFo(pImport->FirstThunk));
			spdlog::debug("In {}:", name);

			while (pThunk->u1.Function) {
				if (pThunk->u1.Function & IMAGE_ORDINAL_FLAG) {
					// Imported by ordinal
					spdlog::debug("\tImported by ordinal: 0x{:x}.", pThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
					data.emplace_back(*pThunk, std::string(), 0);
				}
				else {
					// Imported by name
					auto func = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + rvaToFo(pThunk->u1.Function));
					spdlog::debug("\tImported by name: {} and hint: {}.", func->Name, func->Hint);
					data.emplace_back(*pThunk, func->Name, func->Hint);
				}

				pThunk++;
			}

			ret.emplace_back(name, data);
			pImport++;
		}

		return ret;
	}

	void
		Pe::enumResource(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumException(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumSecurity(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumBasereloc(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumDebug(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumCopyright(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumArchitecture(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumGlobalptr(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumTls(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumLoadConfig(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumBoundImport(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumIat(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumDelayImport(
			void
		)
	{
		// TODO: Not implemented
	}

	void
		Pe::enumComDescriptor(
			void
		)
	{
		// TODO: Not implemented
	}

	//
	//	Offset Translate
	//

	uint64_t
		Pe::vaToRva(
			uint64_t va
		)
	{
		auto vaEntry = getNtHeaders()->getOptionalHeader()->AddressOfEntryPoint;

		if (va < vaEntry) {
			throw std::out_of_range("Address is not in process's virtual range.");
		}

		return va - vaEntry;
	}

	uint64_t
		Pe::rvaToVa(
			uint64_t rva
		) noexcept
	{
		auto vaEntry = getNtHeaders()->getOptionalHeader()->AddressOfEntryPoint;

		return rva + vaEntry;
	}

	uint64_t
		Pe::foToRva(
			uint64_t fo
		)
	{
		auto sec = getSectionByFo(fo);

		return fo - sec.PointerToRawData + sec.VirtualAddress;
	}

	uint64_t
		Pe::rvaToFo(
			uint64_t rva
		)
	{
		auto sec = getSectionByRva(rva);

		return rva - sec.VirtualAddress + sec.PointerToRawData;
	}

	uint64_t
		Pe::foToVa(
			uint64_t fo
		)
	{
		auto sec = getSectionByFo(fo);

		return rvaToVa(fo - sec.PointerToRawData + sec.VirtualAddress);
	}

	uint64_t
		Pe::vaToFo(
			uint64_t va
		)
	{
		auto sec = getSectionByVa(va);

		return vaToRva(va) - sec.VirtualAddress + sec.PointerToRawData;
	}
}
