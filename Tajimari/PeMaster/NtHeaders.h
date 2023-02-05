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
			uint32_t offset
		);

		void
			open(
				uint32_t offset
			);

		void
			open(
				const Buffer& buffer,
				uint32_t offset
			);

		FileHeader&
			getFileHeader(
				void
			);

		OptionalHeader&
			getOptionalHeader(
				void
			);

		size_t
			copyTo(
				uint32_t offset
			);

		size_t
			copyTo(
				Buffer& buffer,
				uint32_t offset
			);

		size_t
			copyToNoAlloc(
				uint32_t offset
			);

		size_t
			copyToNoAlloc(
				Buffer& buffer,
				uint32_t offset
			);

		virtual
			~NtHeaders() = default;

		DWORD Signature = IMAGE_NT_SIGNATURE;

	private:
	};
}
