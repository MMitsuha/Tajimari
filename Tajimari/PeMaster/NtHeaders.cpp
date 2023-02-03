#include "NtHeaders.h"

namespace PeMaster {
	NtHeaders::NtHeaders(
		LONG offset
	)
	{
		spdlog::debug("Nt headers constructed with offset: {}.", offset);
		this->NtHeaders::open(offset);
	}

	void
		NtHeaders::open(
			uint32_t offset
		)
	{
		spdlog::debug("Building nt headers with base object and offset: {}.", offset);
		this->NtHeaders::open(m_buffer, offset);
	}

	void
		NtHeaders::open(
			const std::vector<uint8_t>& buffer,
			uint32_t offset
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building nt headers with given buffer and offset: {}.", offset);
		const auto pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS const*>(buffer.data() + offset);

		// Check nt headers
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			spdlog::error("Not a valid pe file.");
			m_valid = false;
			return;
		}

		// Initialize signature
		Signature = pNtHeaders->Signature;

		// Initialize file header
		auto pFileHeader = dynamic_cast<FileHeader*>(this);
		pFileHeader->FileHeader::open(offset + sizeof(pNtHeaders->Signature));

		// Initialize optional header
		auto pOptionalHeader = dynamic_cast<OptionalHeader*>(this);
		pOptionalHeader->OptionalHeader::open(offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), pFileHeader->SizeOfOptionalHeader);

		m_valid = true;
	}

	FileHeader*
		NtHeaders::getFileHeader(
			void
		)
	{
		return dynamic_cast<FileHeader*>(this);
	}

	OptionalHeader*
		NtHeaders::getOptionalHeader(
			void
		)
	{
		return dynamic_cast<OptionalHeader*>(this);
	}
}
