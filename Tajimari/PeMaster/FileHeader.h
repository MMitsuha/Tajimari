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
			size_t offset
		);

		void
			open(
				size_t offset
			);

		void
			open(
				const Buffer& buffer,
				size_t offset
			);

		void
			copyTo(
				size_t offset
			);

		void
			copyTo(
				Buffer& buffer,
				size_t offset
			);

		void
			copyToNoAlloc(
				size_t offset
			);

		void
			copyToNoAlloc(
				Buffer& buffer,
				size_t offset
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
