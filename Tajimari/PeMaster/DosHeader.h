#pragma once
#include "BaseObject.h"
#include <winnt.h>

namespace PeMaster {
	using DosStub = std::vector<uint8_t>;

	class DosHeader
		:virtual public BaseObject,
		public IMAGE_DOS_HEADER
	{
	public:
		DosHeader();

		void
			open(
				void
			);

		void
			open(
				const Buffer& buffer
			);

		size_t
			copyTo(
				void
			);

		size_t
			copyTo(
				Buffer& buffer
			);

		virtual
			~DosHeader() = default;

		DosStub m_DosStub;

	private:
		void
			copyFrom(
				IMAGE_DOS_HEADER const* pointer
			);
	};
}
