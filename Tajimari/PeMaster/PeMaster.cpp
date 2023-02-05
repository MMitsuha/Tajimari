#include "PeMaster.h"
#include <fstream>
#include <tuple>
#include <queue>
#include <spdlog/spdlog.h>

namespace PeMaster {
	Pe::Pe(
		const std::filesystem::path& path
	)
	{
		spdlog::debug("Pe constructed.");
		open(path);
	}

	bool
		Pe::open(
			const std::filesystem::path& path
		)
	{
		spdlog::debug("Building pe with given path.");
		// Initialize base object
		auto& rBaseObject = asBaseObject();
		auto ret = rBaseObject.open(path);

		open();

		return ret;
	}

	void
		Pe::open(
			const Buffer& buffer
		)
	{
		spdlog::debug("Building pe with given buffer.");
		// Initialize base object
		auto& rBaseObject = asBaseObject();
		rBaseObject.open(buffer);

		open();
	}

	void
		Pe::open(
			void
		)
	{
		// Initialize dos header
		auto& rDosHeader = getDosHeader();
		rDosHeader.open();

		// Initialize nt headers
		auto& rNtHeaders = getNtHeaders();
		rNtHeaders.open(rDosHeader.e_lfanew);

		// Initialize section headers
		WORD i = 0;
		auto& rSectionHeaders = getSectionHeaders();
		rSectionHeaders.resize(rNtHeaders.getFileHeader().NumberOfSections);
		for (auto& sec : rSectionHeaders) {
			sec.open(m_buffer, rDosHeader.e_lfanew // At the beginning of nt headers
				+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + rNtHeaders.getFileHeader().SizeOfOptionalHeader // At the beginning of section headers
				+ i * sizeof(IMAGE_SECTION_HEADER));

			i++;
		}
	}

	bool
		Pe::isValid(
			void
		)
	{
		return m_valid;
	}

	DosHeader&
		Pe::getDosHeader(
			void
		)
	{
		return dynamic_cast<DosHeader&>(*this);
	}

	NtHeaders&
		Pe::getNtHeaders(
			void
		)
	{
		return dynamic_cast<NtHeaders&>(*this);
	}

	SectionHeaders&
		Pe::getSectionHeaders(
			void
		)
	{
		return dynamic_cast<SectionHeaders&>(*this);
	}

	BaseObject&
		Pe::asBaseObject(
			void
		)
	{
		return dynamic_cast<BaseObject&>(*this);
	}

	SectionHeader&
		Pe::getSectionByVa(
			uint64_t va
		)
	{
		auto rva = vaToRva(va);

		return getSectionByRva(rva);
	}

	SectionHeader&
		Pe::getSectionByRva(
			uint64_t rva
		)
	{
		auto& rSectionHeaders = getSectionHeaders();
		for (const auto& sec : rSectionHeaders) {
			if (rva == std::clamp(rva, static_cast<uint64_t>(sec.VirtualAddress),
				static_cast<uint64_t>(sec.VirtualAddress + sec.Misc.VirtualSize))) return const_cast<SectionHeader&>(sec);
		}

		throw std::out_of_range("No section matched given RVA.");
	}

	SectionHeader&
		Pe::getSectionByFo(
			uint64_t fo
		)
	{
		auto& rSectionHeaders = getSectionHeaders();
		for (const auto& sec : rSectionHeaders) {
			if (fo == std::clamp(fo, static_cast<uint64_t>(sec.PointerToRawData),
				static_cast<uint64_t>(sec.PointerToRawData + sec.SizeOfRawData))) return const_cast<SectionHeader&>(sec);
		}

		throw std::out_of_range("No section matched given FO.");
	}

	SectionHeader&
		Pe::getSectionByName(
			const std::string& name
		)
	{
		auto& rSectionHeaders = getSectionHeaders();
		for (const auto& sec : rSectionHeaders) {
			if (name == reinterpret_cast<char const*>(sec.Name)) return const_cast<SectionHeader&>(sec);
		}

		throw std::out_of_range("No section matched given name.");
	}

	//
	//	Pe read: enumerate data dictionary
	//

	Pe::Exports
		Pe::enumExport(
			void
		)
	{
		Exports ret;
		auto importDir = getNtHeaders().getOptionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
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
			std::string funcName = reinterpret_cast<char*>(base + rvaToFo(tableName[i]));
			auto funcOrd = tableOrdName[i] + baseOrdinal;
			auto funcRvaAddr = tableAddr[i];
			ret.emplace_back(funcOrd, funcName, funcRvaAddr);

			spdlog::debug("Ordinal: {}, name: {}, rva: 0x{:x}.", funcOrd, funcName, funcRvaAddr);
		}

		return ret;
	}

	Pe::Imports
		Pe::enumImport(
			void
		)
	{
		Imports ret;
		auto importDir = getNtHeaders().getOptionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto rva = importDir.VirtualAddress;
		auto size = importDir.Size;

		if (rva == 0) {
			return {};
		}

		auto base = m_buffer.data();
		auto pImport = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + rvaToFo(rva));

		while (pImport->Name) {
			std::string name = reinterpret_cast<char*>(base + rvaToFo(pImport->Name));
			auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + rvaToFo(pImport->FirstThunk));
			spdlog::debug("In {}:", name);

			while (pThunk->u1.Function) {
				Import data{};
				if (pThunk->u1.Function & IMAGE_ORDINAL_FLAG) {
					// Imported by ordinal
					spdlog::debug("\tImported by ordinal: 0x{:x}.", pThunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
				}
				else {
					// Imported by name
					auto func = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + rvaToFo(pThunk->u1.Function));
					spdlog::debug("\tImported by name: {} and hint: {}.", func->Name, func->Hint);
					data.ByName.Hint = func->Hint;
					data.ByName.Name = func->Name;
				}

				data.Thunk = *pThunk;
				ret.emplace_back(std::move(data));

				pThunk++;
			}

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

	Pe::Relocs
		Pe::enumBasereloc(
			void
		)
	{
		Relocs ret;
		auto relocsDir = getNtHeaders().getOptionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		auto rva = relocsDir.VirtualAddress;
		auto size = relocsDir.Size;

		if (rva == 0) {
			return {};
		}

		auto base = m_buffer.data();
		auto endOfRelocs = reinterpret_cast<uint8_t*>(base + rvaToFo(rva) + size);
		auto pRelocsBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(base + rvaToFo(rva));
		auto i = 0;
		while (reinterpret_cast<uint8_t*>(pRelocsBlock) < endOfRelocs) {
			auto numRelocsInBlock = (pRelocsBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			auto reloc = reinterpret_cast<uint16_t*>(pRelocsBlock + 1);
			for (uint32_t i = 0; i < numRelocsInBlock; i++) {
				auto type = reloc[i] >> 12;
				auto offset = reloc[i] & 0x0FFF;
				auto rvaReloc = pRelocsBlock->VirtualAddress + offset;
				ret.emplace_back(type, rvaReloc);

				spdlog::debug("{}: Relocation type: {}, rva: 0x{:x}", i, type, rvaReloc);
			}

			pRelocsBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(pRelocsBlock) + pRelocsBlock->SizeOfBlock);
			i++;
		}

		return ret;
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
	//	Pe write
	//

	bool
		Pe::rebuild(
			void
		)
	{
		m_buffer.clear();
		auto& rDosHeader = getDosHeader();
		auto& rNtHeaders = getNtHeaders();
		auto& rSectionHeaders = getSectionHeaders();
		size_t offset = 0;
		size_t offsetHeaders = 0;

		// Copy dos header
		offset = rDosHeader.copyTo();
		// Update dos header
		rDosHeader.open();
		// Check e_lfanew
		if (rDosHeader.e_lfanew < offset) {
			spdlog::warn("Nt headers overwrite dos header field.");
		}

		// Update section number
		rNtHeaders.getFileHeader().NumberOfSections = rSectionHeaders.size();
		// Copy nt headers
		offset = rNtHeaders.copyTo(rDosHeader.e_lfanew);
		// Update nt headers
		rNtHeaders.open(rDosHeader.e_lfanew);

		std::queue<uint64_t> oldOffsets;
		for (auto& sec : rSectionHeaders) {
			// Backup offset
			oldOffsets.push(offset);
			// Copy section header
			offset = sec.copyHeaderTo(m_buffer, offset);
		}
		offsetHeaders = align_up(offset, rNtHeaders.getOptionalHeader().FileAlignment);
		uint64_t rvaLastSectionEnd = 0;
		uint32_t sizeOfCode = 0;
		uint32_t sizeOfInitedData = 0;
		uint32_t sizeOfUninitedData = 0;
		for (auto& sec : rSectionHeaders) {
			auto oldOffset = oldOffsets.front();
			oldOffsets.pop();
			bool updateRequired = false;
			// Check if the content offset is smaller than current offset,
			// if true, then set it to current offset
			if (sec.PointerToRawData < offset) {
				sec.PointerToRawData = align_up(offset, rNtHeaders.getOptionalHeader().FileAlignment);
				updateRequired = true;
			}
			// Check if the virtual address conflict with other section,
			// if true, then set it to the nearest end and align it
			if (sec.VirtualAddress < rvaLastSectionEnd) {
				sec.VirtualAddress = align_up(rvaLastSectionEnd, rNtHeaders.getOptionalHeader().SectionAlignment);
				updateRequired = true;
			}
			// If we modified the header, we must write it back
			if (updateRequired) {
				sec.copyHeaderTo(m_buffer, oldOffset);
			}
			// Check if the section has code attribute and add to size of code
			if (sec.Characteristics & IMAGE_SCN_CNT_CODE) sizeOfCode += sec.Misc.VirtualSize;
			// Check if the section has initialized data attribute and add to size of initialized data
			if (sec.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) sizeOfInitedData += sec.Misc.VirtualSize;
			// Check if the section has code attribute and add to size of code
			if (sec.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) sizeOfUninitedData += sec.Misc.VirtualSize;
			// Copy section content
			offset = sec.copyContentTo(m_buffer, sec.PointerToRawData);
			// Update section header
			sec.open(m_buffer, oldOffset);
			rvaLastSectionEnd = sec.VirtualAddress + sec.Misc.VirtualSize;
		}

		// Update sizes and checksum
		rvaLastSectionEnd = align_up(rvaLastSectionEnd, rNtHeaders.getOptionalHeader().SectionAlignment);
		sizeOfCode = align_up(sizeOfCode, rNtHeaders.getOptionalHeader().SectionAlignment);
		sizeOfInitedData = align_up(sizeOfInitedData, rNtHeaders.getOptionalHeader().SectionAlignment);
		sizeOfUninitedData = align_up(sizeOfUninitedData, rNtHeaders.getOptionalHeader().SectionAlignment);
		rNtHeaders.getOptionalHeader().SizeOfImage = rvaLastSectionEnd;
		rNtHeaders.getOptionalHeader().SizeOfCode = sizeOfCode;
		rNtHeaders.getOptionalHeader().SizeOfInitializedData = sizeOfInitedData;
		rNtHeaders.getOptionalHeader().SizeOfUninitializedData = sizeOfUninitedData;
		rNtHeaders.getOptionalHeader().SizeOfHeaders = offsetHeaders;
		rNtHeaders.getOptionalHeader().CheckSum = computeChecksum();
		// Don't re-alloc
		rNtHeaders.copyToNoAlloc(rDosHeader.e_lfanew);

		// Update checksum

		return true;
	}

	bool
		Pe::write(
			const std::filesystem::path& path
		)
	{
		if (!m_valid) return false;

		std::ofstream file(path, std::ios_base::binary);

		if (!file.is_open()) return false;

		std::copy(m_buffer.cbegin(), m_buffer.cend(), std::ostreambuf_iterator<char>(file));
		return true;
	}

	void
		Pe::write(
			Buffer& buffer
		)
	{
		buffer.clear();
		std::copy(m_buffer.cbegin(), m_buffer.cend(), buffer.begin());
	}

	//
	//	Offset Translate
	//

	uint64_t
		Pe::vaToRva(
			uint64_t va
		)
	{
		auto vaEntry = getNtHeaders().getOptionalHeader().AddressOfEntryPoint;

		if (va < vaEntry) {
			spdlog::error("Va: 0x{:x} is not in process's memory range.", va);
		}

		return va - vaEntry;
	}

	uint64_t
		Pe::rvaToVa(
			uint64_t rva
		)
	{
		auto vaEntry = getNtHeaders().getOptionalHeader().AddressOfEntryPoint;

		return rva + vaEntry;
	}

	uint64_t
		Pe::foToRva(
			uint64_t fo
		)
	{
		auto& sec = getSectionByFo(fo);

		return fo - sec.PointerToRawData + sec.VirtualAddress;
	}

	uint64_t
		Pe::rvaToFo(
			uint64_t rva
		)
	{
		auto& sec = getSectionByRva(rva);

		return rva - sec.VirtualAddress + sec.PointerToRawData;
	}

	uint64_t
		Pe::foToVa(
			uint64_t fo
		)
	{
		auto& sec = getSectionByFo(fo);

		return rvaToVa(fo - sec.PointerToRawData + sec.VirtualAddress);
	}

	uint64_t
		Pe::vaToFo(
			uint64_t va
		)
	{
		auto& sec = getSectionByVa(va);

		return vaToRva(va) - sec.VirtualAddress + sec.PointerToRawData;
	}

	bool
		Pe::validVa(
			uint64_t va
		)
	{
		if (va > getNtHeaders().getOptionalHeader().SizeOfImage) return false;

		return true;
	}

	bool
		Pe::validRva(
			uint64_t rva
		)
	{
		if (vaToRva(rva) > getNtHeaders().getOptionalHeader().SizeOfImage) return false;

		return true;
	}

	bool
		Pe::validFo(
			uint64_t fo
		)
	{
		if (fo > m_buffer.size()) return false;

		return true;
	}

	uint32_t
		Pe::computeChecksum(
			void
		)
	{
		static const uint16_t posChecksum = 64;
		static const uint32_t top = 0xFFFFFFFF;
		uint64_t checksum = 0;
		auto base = m_buffer.data();
		for (size_t i = 0; i < m_buffer.size(); i += sizeof(uint32_t))
		{
			uint32_t dw = *reinterpret_cast<uint32_t*>(base + i);

			//Skip "CheckSum" pos
			if (i == posChecksum) continue;

			// Calculate checksum
			checksum = (checksum & 0xffffffff) + dw + (checksum >> 32);
			if (checksum > top)
				checksum = (checksum & 0xffffffff) + (checksum >> 32);
		}

		//Finish checksum
		checksum = (checksum & 0xffff) + (checksum >> 16);
		checksum = (checksum)+(checksum >> 16);
		checksum = checksum & 0xffff;

		checksum += m_buffer.size();

		return static_cast<uint32_t>(checksum);
	}
}
