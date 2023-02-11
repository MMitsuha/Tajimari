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
		// TODO: Support forwarder chain

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
			ImportEntry entry;
			std::string name = reinterpret_cast<char*>(base + rvaToFo(pImport->Name));
			auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + rvaToFo(pImport->FirstThunk));
			spdlog::debug("In {}:", name);
			entry.DllName = std::move(name);
			entry.IsBound = pImport->TimeDateStamp == -1;

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
				entry.Table.emplace_back(std::move(data));
				pThunk++;
			}

			ret.emplace_back(std::move(entry));
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

	void
		Pe::setImport(
			Imports& imports
		)
	{
		// TODO: Support forwarder chain
		// Generate a new section
		SectionHeader secImport;
		auto& secAdded = getSectionHeaders().emplace_back(secImport);
		// Set name
		secAdded.Name[0] = '.';
		secAdded.Name[1] = 'i';

		// Get information
		auto& content = secAdded.m_content;
		auto& importDir = getNtHeaders().getOptionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto& rva = importDir.VirtualAddress;
		auto& size = importDir.Size;

		// Get size
		uint64_t sizeOfDescriptors = imports.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		uint64_t sizeOfNames = 0;
		uint64_t sizeOfByNames = 0;
		uint64_t sizeOfThunks = 0;

		for (const auto& entry : imports) {
			sizeOfNames += entry.DllName.size() + 1;
			sizeOfThunks += sizeof(IMAGE_THUNK_DATA) * entry.Table.size();

			for (const auto& imp : entry.Table) {
				// Filter functions imported by name
				if ((imp.Thunk.u1.Function & IMAGE_ORDINAL_FLAG) == 0) {
					sizeOfByNames += imp.ByName.Name.size() + 1 + sizeof(WORD);
				}
			}
		}

		sizeOfDescriptors += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		sizeOfThunks += imports.size() * sizeof(IMAGE_THUNK_DATA);

		auto total = sizeOfDescriptors + sizeOfNames + sizeOfByNames + sizeOfThunks * 2;
		auto totalFAligned = align_up(total, getNtHeaders().getOptionalHeader().FileAlignment);
		auto totalSAligned = align_up(total, getNtHeaders().getOptionalHeader().SectionAlignment);
		content.resize(totalFAligned);
		secAdded.SizeOfRawData = totalFAligned;
		secAdded.Misc.VirtualSize = totalSAligned;

		rebuild();
		rva = secAdded.VirtualAddress;
		size = total;

		auto pDescriptorStart = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(content.data());
		for (const auto& entry : imports) {
			pDescriptorStart->ForwarderChain = 0;
			pDescriptorStart->TimeDateStamp = entry.IsBound ? -1 : 0;

			pDescriptorStart++;
		}

		size_t i = 0;
		pDescriptorStart = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(content.data());
		auto pDllNameStart = content.data() + sizeOfDescriptors + sizeOfThunks * 2;
		for (const auto& entry : imports) {
			pDescriptorStart[i].Name = pDllNameStart - content.data() + rva;
			std::copy(entry.DllName.cbegin(), entry.DllName.cend(), pDllNameStart);
			pDllNameStart += entry.DllName.size() + 1;

			i++;
		}

		i = 0;
		size_t j = 0;
		pDescriptorStart = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(content.data());
		auto pThunkStart = reinterpret_cast<PIMAGE_THUNK_DATA>(content.data() + sizeOfDescriptors);
		auto pOThunkStart = reinterpret_cast<PIMAGE_THUNK_DATA>(content.data() + sizeOfDescriptors + sizeOfThunks);
		auto pByNameStart = content.data() + sizeOfDescriptors + sizeOfThunks * 2 + sizeOfNames;
		for (const auto& entry : imports) {
			pDescriptorStart[i].FirstThunk = reinterpret_cast<uint8_t*>(&pThunkStart[j]) - content.data() + rva;
			//pDescriptorStart[i].OriginalFirstThunk = reinterpret_cast<uint8_t*>(&pOThunkStart[j]) - content.data() + rva;
			for (const auto& imp : entry.Table) {
				// Filter functions imported by name
				if ((imp.Thunk.u1.Function & IMAGE_ORDINAL_FLAG) == 0) {
					pThunkStart[j].u1.Function = pByNameStart - content.data() + rva;
					//pOThunkStart[j].u1.Function = pByNameStart - content.data() + rva;

					*reinterpret_cast<WORD*>(pByNameStart) = imp.ByName.Hint;
					memcpy(pByNameStart + sizeof(WORD), imp.ByName.Name.data(), imp.ByName.Name.size());
					//pByNameStart += sizeof(WORD) + imp.ByName.Name.size() + 1;
					pByNameStart += sizeof(WORD) + imp.ByName.Name.size();
					//if (reinterpret_cast<uint64_t>(pByNameStart) % 2 != 0) pByNameStart++;

					j++;
				}
			}

			// Leave a blank thunk
			j++;
			i++;
		}

		rebuild();
	}

	size_t
		Pe::updateHeaders(
			void
		)
	{
		// Total raw size
		size_t totalSize = 0;
		// Get all headers
		auto& rDosHeader = getDosHeader();
		auto& rNtHeaders = getNtHeaders();
		auto& rSectionHeaders = getSectionHeaders();
		auto& rOptionalHeader = rNtHeaders.getOptionalHeader();
		auto& rFileHeader = rNtHeaders.getFileHeader();

		// Set e_lfanew to a correct value
		rDosHeader.e_lfanew = std::max<size_t>(rDosHeader.e_lfanew, rDosHeader.totalSize());
		// Add the size of dos header to totalSize
		totalSize += rDosHeader.totalSize();
		// The start position of nt headers
		auto posNtHeaders = totalSize;

		// Add the size of nt headers to totalSize
		totalSize += rNtHeaders.totalSize();
		// The start position of section headers
		auto posSectionHeaders = totalSize;

		// Add the size of section headers to totalSize
		totalSize += rSectionHeaders.size() * sizeof(IMAGE_SECTION_HEADER);
		// The total size of headers
		auto sizeOfHeaders = align_up(totalSize, rOptionalHeader.FileAlignment);
		// The start position of section contents in file offset
		auto posContentFo = sizeOfHeaders;
		// The start position of section contents in rva
		auto posContentRva = align_up(totalSize, rOptionalHeader.SectionAlignment);
		uint32_t sizeOfCode = 0;
		uint32_t sizeOfInitedData = 0;
		uint32_t sizeOfUninitedData = 0;
		for (auto& rSection : rSectionHeaders) {
			// Correct the parameters that users don't give correctly
			rSection.SizeOfRawData = rSection.m_content.size();
			rSection.PointerToRawData = align_up(rSection.PointerToRawData, rOptionalHeader.FileAlignment);
			// Check if the content offset is smaller than current offset,
			// if true, then set it to current offset
			rSection.PointerToRawData = std::max<size_t>(rSection.PointerToRawData, posContentFo);
			rSection.VirtualAddress = align_up(rSection.VirtualAddress, rOptionalHeader.SectionAlignment);
			// Check if the rva conflict with other section,
			// if true, then set it to the nearest end and align it
			rSection.VirtualAddress = std::max<size_t>(rSection.VirtualAddress, posContentRva);

			// Add the content size to totalSize
			totalSize = static_cast<size_t>(rSection.PointerToRawData) + rSection.SizeOfRawData;

			// Move the posContentFo to next content
			posContentFo = align_up(totalSize, rOptionalHeader.FileAlignment);
			// Move the posContentRva to next content
			posContentRva = align_up(static_cast<size_t>(rSection.VirtualAddress) + rSection.Misc.VirtualSize, rOptionalHeader.SectionAlignment);

			// Check if the section has code attribute and add to size of code
			if (rSection.Characteristics & IMAGE_SCN_CNT_CODE) sizeOfCode += rSection.Misc.VirtualSize;
			// Check if the section has initialized data attribute and add to size of initialized data
			if (rSection.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) sizeOfInitedData += rSection.Misc.VirtualSize;
			// Check if the section has code attribute and add to size of code
			if (rSection.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) sizeOfUninitedData += rSection.Misc.VirtualSize;
		}

		// Update sizes
		sizeOfCode = align_up(sizeOfCode, rOptionalHeader.SectionAlignment);
		sizeOfInitedData = align_up(sizeOfInitedData, rOptionalHeader.SectionAlignment);
		sizeOfUninitedData = align_up(sizeOfUninitedData, rOptionalHeader.SectionAlignment);
		rOptionalHeader.SizeOfImage = posContentRva;
		rOptionalHeader.SizeOfCode = sizeOfCode;
		rOptionalHeader.SizeOfInitializedData = sizeOfInitedData;
		rOptionalHeader.SizeOfUninitializedData = sizeOfUninitedData;
		rOptionalHeader.SizeOfHeaders = sizeOfHeaders;

		// Update section numbers
		rFileHeader.NumberOfSections = rSectionHeaders.size();

		// Update checksum

		return totalSize;
	}

	bool
		Pe::rebuild(
			void
		)
	{
		size_t offset = 0;
		auto totalSize = updateHeaders();
		m_buffer.clear();
		m_buffer.resize(totalSize);
		// Get all headers
		auto& rDosHeader = getDosHeader();
		auto& rNtHeaders = getNtHeaders();
		auto& rSectionHeaders = getSectionHeaders();
		auto& rOptionalHeader = rNtHeaders.getOptionalHeader();
		auto& rFileHeader = rNtHeaders.getFileHeader();

		// Copy dos header
		rDosHeader.copyToNoAlloc();
		// Copy nt headers
		offset = rNtHeaders.copyToNoAlloc(rDosHeader.e_lfanew);
		// Copy section headers
		for (auto& rSection : rSectionHeaders) {
			auto oldOffset = offset;
			// Copy section header
			offset = rSection.copyHeaderToNoAlloc(m_buffer, offset);
			// Copy section content
			rSection.copyContentToNoAlloc(m_buffer, rSection.PointerToRawData);
			rSection.open(m_buffer, oldOffset);
		}

		rDosHeader.open();
		rNtHeaders.open(rDosHeader.e_lfanew);

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
