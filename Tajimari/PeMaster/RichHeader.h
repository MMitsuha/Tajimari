#pragma once
#include "BaseObject.h"
#include <winnt.h>

typedef struct _PRODITEM {
	uint32_t dwProdId;
	uint32_t dwCount;
}PRODITEM;

typedef struct _IMAGE_RICH_HEADER {
	PRODITEM DansTag;
	PRODITEM Empty;
}IMAGE_RICH_HEADER, * PIMAGE_RICH_HEADER;

namespace PeMaster {
	class RichHeader
		:virtual public BaseObject
	{
	public:
		RichHeader();

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
			~RichHeader() = default;

	private:
		void
			copyFrom(
				IMAGE_DOS_HEADER const* pointer
			);
	};
}
