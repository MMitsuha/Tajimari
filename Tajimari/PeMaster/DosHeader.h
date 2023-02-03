#pragma once
#include "BaseObject.h"
#include <winnt.h>

namespace PeMaster {
	class DosHeader
		:virtual public BaseObject,
		public IMAGE_DOS_HEADER
	{
	public:
		DosHeader();

		virtual
			void
			open(
				void
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer
			);

		virtual
			~DosHeader() = default;

	private:
		void
			copyFrom(
				IMAGE_DOS_HEADER const* pointer
			);
	};
}
