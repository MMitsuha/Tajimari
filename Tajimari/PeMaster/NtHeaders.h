#pragma once
#include "BaseObject.h"
#include "FileHeader.h"
#include "OptionalHeader.h"
#include <winnt.h>

namespace PeMaster {
	class NtHeaders
		:virtual public BaseObject,
		private FileHeader,
		private OptionalHeader
	{
	public:
		NtHeaders() = default;
		NtHeaders(
			LONG offset
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

		FileHeader*
			getFileHeader(
				void
			);

		OptionalHeader*
			getOptionalHeader(
				void
			);

		virtual
			~NtHeaders() = default;

		DWORD Signature = IMAGE_NT_SIGNATURE;

	private:
	};
}
