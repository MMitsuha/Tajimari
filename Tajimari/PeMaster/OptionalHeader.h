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
			size_t offset,
			size_t size
		);

		void
			open(
				size_t offset,
				size_t size
			);

		void
			open(
				const Buffer& buffer,
				size_t offset,
				size_t size
			);

		void
			copyTo(
				size_t offset,
				size_t size
			);

		void
			copyTo(
				Buffer& buffer,
				size_t offset,
				size_t size
			);

		void
			copyToNoAlloc(
				size_t offset,
				size_t size
			);

		void
			copyToNoAlloc(
				Buffer& buffer,
				size_t offset,
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
