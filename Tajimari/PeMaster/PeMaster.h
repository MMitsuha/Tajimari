#pragma once
#include <filesystem>
#include <vector>
#include <windows.h>

#include "DosHeader.h"
#include "NtHeaders.h"
#include "SectionHeader.h"

namespace PeMaster {
	class Pe
		:virtual public BaseObject,
		private DosHeader,
		private NtHeaders
	{
	public:
		Pe() = default;

		Pe(
			const std::filesystem::path& path
		);

		virtual
			bool
			open(
				const std::filesystem::path& buffer
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer
			);

		bool
			isValid(
				void
			);

		DosHeader*
			getDosHeader(
				void
			);

		NtHeaders*
			getNtHeaders(
				void
			);

		std::vector<SectionHeader>*
			getSectionHeaders(
				void
			);

		BaseObject*
			asBaseObject(
				void
			);

		SectionHeader
			getSectionByVa(
				uint64_t va
			);

		SectionHeader
			getSectionByRva(
				uint64_t rva
			);

		SectionHeader
			getSectionByFo(
				uint64_t fo
			);

		//
		//	Pe read: enumerate data dictionary
		//

		std::vector<std::tuple<uint16_t, std::string, void*>>
			enumExport(
				void
			);

		std::vector<std::pair<std::string, std::vector<std::tuple<IMAGE_THUNK_DATA, std::string, WORD>>>>
			enumImport(
				void
			);

		void
			enumResource(
				void
			);

		void
			enumException(
				void
			);

		void
			enumSecurity(
				void
			);

		void
			enumBasereloc(
				void
			);

		void
			enumDebug(
				void
			);

		void
			enumCopyright(
				void
			);

		void
			enumArchitecture(
				void
			);

		void
			enumGlobalptr(
				void
			);

		void
			enumTls(
				void
			);

		void
			enumLoadConfig(
				void
			);

		void
			enumBoundImport(
				void
			);

		void
			enumIat(
				void
			);

		void
			enumDelayImport(
				void
			);

		void
			enumComDescriptor(
				void
			);

		//
		//	Offset Translate
		//

		uint64_t
			vaToRva(
				uint64_t va
			);

		uint64_t
			rvaToVa(
				uint64_t rva
			) noexcept;

		uint64_t
			foToRva(
				uint64_t fo
			);

		uint64_t
			rvaToFo(
				uint64_t rva
			);

		uint64_t
			foToVa(
				uint64_t fo
			);

		uint64_t
			vaToFo(
				uint64_t va
			);

		virtual
			~Pe() = default;

	private:
		std::vector<uint8_t> m_DosStub;

		std::vector<SectionHeader> m_SectionHeaders;
	};
}
