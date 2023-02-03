#include "SectionHeader.h"

namespace PeMaster {
	SectionHeader::SectionHeader(
		uint64_t offset
	)
	{
		spdlog::debug("Section header constructed with offset: {}.", offset);
		this->SectionHeader::open(offset);
	}

	void
		SectionHeader::open(
			uint64_t offset
		)
	{
		spdlog::debug("Building section header with base object and offset: {}.", offset);
		this->SectionHeader::open(m_buffer, offset);
	}

	void
		SectionHeader::open(
			const std::vector<uint8_t>& buffer,
			uint64_t offset
		)
	{
		spdlog::debug("Building section header with given buffer and offset: {}.", offset);
		const auto pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER const*>(buffer.data() + offset);

		// Copy header to myself
		this->copyHeaderFrom(pSectionHeader);

		// Copy content to myself
		if (this->PointerToRawData) {
			const auto pContent = reinterpret_cast<void const*>(buffer.data() + this->PointerToRawData);
			this->copyContentFrom(pContent, this->SizeOfRawData);
		}

		m_valid = true;
	}

	void
		SectionHeader::copyHeaderFrom(
			IMAGE_SECTION_HEADER const* pointer
		)
	{
		spdlog::debug("Copied to section header.");
		auto pSectionHeader = dynamic_cast<PIMAGE_SECTION_HEADER>(this);
		memcpy(pSectionHeader, pointer, sizeof(IMAGE_SECTION_HEADER));
	}

	void
		SectionHeader::copyContentFrom(
			const void* pointer,
			size_t size
		)
	{
		spdlog::debug("Copied to section content with size: {}.", size);
		content.clear();
		auto buffer = reinterpret_cast<const uint8_t*>(pointer);
		std::copy(buffer, buffer + size, std::back_inserter(content));
	}
}
