#pragma once
#include "BaseObject.h"
#include <winnt.h>

namespace PeMaster {
	class FileHeader
		:virtual public BaseObject,
		public IMAGE_FILE_HEADER
	{
	public:
		FileHeader() = default;
		FileHeader(
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

		void
			copyTo(
				uint64_t offset
			);

		void
			copyTo(
				Buffer& buffer,
				uint64_t offset
			);

		void
			copyToNoAlloc(
				uint64_t offset
			);

		void
			copyToNoAlloc(
				Buffer& buffer,
				uint64_t offset
			);

		virtual
			~FileHeader() = default;

	private:
		void
			copyFrom(
				IMAGE_FILE_HEADER const* pointer
			);
	};
}
