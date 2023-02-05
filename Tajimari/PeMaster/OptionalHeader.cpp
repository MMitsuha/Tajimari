#include "OptionalHeader.h"

namespace PeMaster {
	OptionalHeader::OptionalHeader(
		uint64_t offset,
		size_t size
	)
	{
		spdlog::debug("Optional header constructed with offset: {} and size: {}.", offset, size);
		open(offset, size);
	}

	void
		OptionalHeader::open(
			uint64_t offset,
			size_t size
		)
	{
		spdlog::debug("Building optional header with base object and offset: {} and size: {}.", offset, size);
		open(m_buffer, offset, size);
	}

	void
		OptionalHeader::open(
			const Buffer& buffer,
			uint64_t offset,
			size_t size
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building optional header with given buffer and offset: {} and size: {}.", offset, size);
		const auto pOptionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER const*>(buffer.data() + offset);

		// Copy to myself
		copyFrom(pOptionalHeader, size);
		m_valid = true;
	}

	void
		OptionalHeader::copyTo(
			uint64_t offset,
			size_t size
		)
	{
		copyTo(m_buffer, offset, size);
	}

	void
		OptionalHeader::copyTo(
			Buffer& buffer,
			uint64_t offset,
			size_t size
		)
	{
		auto pointer = reinterpret_cast<uint8_t*>(dynamic_cast<PIMAGE_OPTIONAL_HEADER>(this));
		buffer.resize(offset + size);
		std::copy(pointer, pointer + size, buffer.begin() + offset);
	}

	void
		OptionalHeader::copyFrom(
			IMAGE_OPTIONAL_HEADER const* pointer,
			size_t size
		)
	{
		spdlog::debug("Copied to optional header with size: {}.", size);
		auto pOptionalHeader = dynamic_cast<PIMAGE_OPTIONAL_HEADER>(this);
		memset(pOptionalHeader, 0, sizeof(IMAGE_OPTIONAL_HEADER));
		memcpy(pOptionalHeader, pointer, size);
	}
}
