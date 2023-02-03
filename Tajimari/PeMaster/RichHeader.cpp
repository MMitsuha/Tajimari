#include "RichHeader.h"

namespace PeMaster {
	RichHeader::RichHeader()
	{
		spdlog::debug("Rich header constructed.");
		this->RichHeader::open();
	}

	void
		RichHeader::open(
			void
		)
	{
		spdlog::debug("Building rich header with base object.");
		this->RichHeader::open(m_buffer);
	}

	void
		RichHeader::open(
			const std::vector<uint8_t>& buffer
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building rich header with given buffer.");
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
		RichHeader::copyFrom(
			IMAGE_DOS_HEADER const* pointer
		)
	{
		spdlog::debug("Copied to dos header");
		auto pDosHeader = dynamic_cast<PIMAGE_DOS_HEADER>(this);
		memcpy(pDosHeader, pointer, sizeof(IMAGE_DOS_HEADER));
	}
}
