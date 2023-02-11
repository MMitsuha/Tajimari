#include "DosHeader.h"

namespace PeMaster {
	DosHeader::DosHeader()
	{
		spdlog::debug("Dos header constructed.");
		open();
	}

	void
		DosHeader::open(
			void
		)
	{
		spdlog::debug("Building dos header with base object.");
		open(m_buffer);
	}

	void
		DosHeader::open(
			const Buffer& buffer
		)
	{
		if (buffer.empty()) {
			m_valid = false;
			return;
		}

		spdlog::debug("Building dos header with given buffer.");
		const auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER const*>(buffer.data());
		const auto pointer = reinterpret_cast<IMAGE_DOS_HEADER const*>(buffer.data());

		// Check dos header
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			spdlog::error("Not a valid pe file.");
			m_valid = false;
			return;
		}

		// Copy to myself
		copyFrom(pDosHeader);

		// TODO: parse rich header

		// Initialize dos stub
		m_DosStub.resize(pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER));
		std::copy(m_buffer.cbegin() + sizeof(IMAGE_DOS_HEADER),
			m_buffer.cbegin() + pDosHeader->e_lfanew,
			m_DosStub.begin());

		m_valid = true;
	}

	size_t
		DosHeader::copyTo(
			void
		)
	{
		return copyTo(m_buffer);
	}

	size_t
		DosHeader::copyTo(
			Buffer& buffer
		)
	{
		auto pointer = reinterpret_cast<uint8_t*>(dynamic_cast<PIMAGE_DOS_HEADER>(this));
		buffer.resize(sizeof(IMAGE_DOS_HEADER) + m_DosStub.size());
		std::copy(pointer, pointer + sizeof(IMAGE_DOS_HEADER), buffer.begin());
		std::copy(m_DosStub.cbegin(), m_DosStub.cend(), buffer.begin() + sizeof(IMAGE_DOS_HEADER));
		return sizeof(IMAGE_DOS_HEADER) + m_DosStub.size();
	}

	size_t
		DosHeader::copyToNoAlloc(
			void
		)
	{
		return copyToNoAlloc(m_buffer);
	}

	size_t
		DosHeader::copyToNoAlloc(
			Buffer& buffer
		)
	{
		auto pointer = reinterpret_cast<uint8_t*>(dynamic_cast<PIMAGE_DOS_HEADER>(this));
		std::copy(pointer, pointer + sizeof(IMAGE_DOS_HEADER), buffer.begin());
		std::copy(m_DosStub.cbegin(), m_DosStub.cend(), buffer.begin() + sizeof(IMAGE_DOS_HEADER));
		return sizeof(IMAGE_DOS_HEADER) + m_DosStub.size();
	}

	size_t
		DosHeader::totalSize(
			void
		)
	{
		return sizeof(IMAGE_DOS_HEADER) + m_DosStub.size();
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
