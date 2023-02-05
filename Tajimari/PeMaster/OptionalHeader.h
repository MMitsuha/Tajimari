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
			uint64_t offset,
			size_t size
		);

		void
			open(
				uint64_t offset,
				size_t size
			);

		void
			open(
				const Buffer& buffer,
				uint64_t offset,
				size_t size
			);

		void
			copyTo(
				uint64_t offset,
				size_t size
			);

		void
			copyTo(
				Buffer& buffer,
				uint64_t offset,
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
