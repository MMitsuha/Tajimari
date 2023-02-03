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
			uint32_t offset
		);

		virtual
			void
			open(
				uint32_t offset
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer,
				uint32_t offset
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
