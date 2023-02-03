#include "DosHeader.h"

namespace PeMaster {
	DosHeader::DosHeader()
	{
		spdlog::debug("Dos header constructed.");
		this->DosHeader::open();
	}

	void
		DosHeader::open(
			void
		)
	{
		spdlog::debug("Building dos header with base object.");
		this->DosHeader::open(m_buffer);
	}

	void
		DosHeader::open(
			const std::vector<uint8_t>& buffer
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building dos header with given buffer.");
		const auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER const*>(buffer.data());

		// Check dos header
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			spdlog::error("Not a valid pe file.");
			m_valid = false;
			return;
		}

		// Copy to myself
		this->copyFrom(pDosHeader);
		m_valid = true;
	}

	void
		DosHeader::copyFrom(
			IMAGE_DOS_HEADER const* pointer
		)
	{
		spdlog::debug("Copied to dos header");
		auto pDosHeader = dynamic_cast<PIMAGE_DOS_HEADER>(this);
		memcpy(pDosHeader, pointer, sizeof(IMAGE_DOS_HEADER));
	}
}
