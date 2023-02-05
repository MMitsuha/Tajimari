#pragma once
#include "BaseObject.h"
#include <winnt.h>
#include <list>

static constexpr uintptr_t align_down(uintptr_t p, size_t align) {
	return p & ~(align - 1);
}

static constexpr uintptr_t align_up(uintptr_t p, size_t align) {
	return (p + align - 1) & ~(align - 1);
}

template <typename T>
static inline T* align_down(T* p, size_t align) {
	return reinterpret_cast<T*>(align_down(reinterpret_cast<uintptr_t>(p), align));
}

template <typename T>
static inline T* align_up(T* p, size_t align) {
	return reinterpret_cast<T*>(align_up(reinterpret_cast<uintptr_t>(p), align));
}

namespace PeMaster {
	class SectionHeader
		:virtual public BaseObject,
		public IMAGE_SECTION_HEADER
	{
	public:
		SectionHeader() = default;
		SectionHeader(
			uint64_t offset
		);

		void
			open(
				uint64_t offset
			);

		void
			open(
				const Buffer& buffer,
				uint64_t offset
			);

		size_t
			copyHeaderTo(
				uint64_t offset
			);

		size_t
			copyHeaderTo(
				Buffer& buffer,
				uint64_t offset
			);

		size_t
			copyContentTo(
				uint64_t offset,
				DWORD fileAlign
			);

		size_t
			copyContentTo(
				Buffer& buffer,
				uint64_t offset,
				DWORD fileAlign
			);

		size_t
			copyContentTo(
				Buffer& buffer,
				uint64_t offset,
				Buffer& content,
				DWORD fileAlign
			);

		virtual
			~SectionHeader() = default;

		Buffer m_content;

	private:
		void
			copyHeaderFrom(
				IMAGE_SECTION_HEADER const* pointer
			);

		void
			copyContentFrom(
				const void* pointer,
				size_t size
			);
	};

	using SectionHeaders = std::list<SectionHeader>;
}
