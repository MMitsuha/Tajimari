#pragma once
#include "BaseObject.h"
#include <winnt.h>

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

		virtual
			void
			open(
				uint64_t offset
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer,
				uint64_t offset
			);

		virtual
			~SectionHeader() = default;

		std::vector<uint8_t> content;

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
}
