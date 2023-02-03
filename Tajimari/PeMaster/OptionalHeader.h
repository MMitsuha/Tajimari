#pragma once
#include "BaseObject.h"
#include <winnt.h>

namespace PeMaster {
	class OptionalHeader
		:virtual public BaseObject,
		public IMAGE_OPTIONAL_HEADER
	{
	public:
		OptionalHeader() = default;
		OptionalHeader(
			uint32_t offset,
			size_t size
		);

		virtual
			void
			open(
				uint32_t offset,
				size_t size
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer,
				uint32_t offset,
				size_t size
			);

		virtual
			~OptionalHeader() = default;

	private:
		void
			copyFrom(
				IMAGE_OPTIONAL_HEADER const* pointer,
				size_t size
			);
	};
}
