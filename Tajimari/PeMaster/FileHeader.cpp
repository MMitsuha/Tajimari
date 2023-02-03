#include "FileHeader.h"

namespace PeMaster {
	FileHeader::FileHeader(
		uint32_t offset
	)
	{
		spdlog::debug("File header constructed with offset: {}.", offset);
		this->FileHeader::open(offset);
	}

	void
		FileHeader::open(
			uint32_t offset
		)
	{
		spdlog::debug("Building file header with base object and offset: {}.", offset);
		this->FileHeader::open(m_buffer, offset);
	}

	void
		FileHeader::open(
			const std::vector<uint8_t>& buffer,
			uint32_t offset
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building file header with given buffer and offset: {}.", offset);
		const auto pFileHeader = reinterpret_cast<IMAGE_FILE_HEADER const*>(buffer.data() + offset);

		// Copy to myself
		this->copyFrom(pFileHeader);
		m_valid = true;
	}

	void
		FileHeader::copyFrom(
			IMAGE_FILE_HEADER const* pointer
		)
	{
		spdlog::debug("Copied to file header.");
		auto pFileHeader = dynamic_cast<PIMAGE_FILE_HEADER>(this);
		memcpy(pFileHeader, pointer, sizeof(IMAGE_FILE_HEADER));
	}
}
