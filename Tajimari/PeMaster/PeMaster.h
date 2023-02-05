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
		private NtHeaders,
		private SectionHeaders
	{
	public:
		Pe() = default;

		Pe(
			const std::filesystem::path& path
		);

		bool
			open(
				const std::filesystem::path& buffer
			);

		void
			open(
				const Buffer& buffer
			);

		bool
			isValid(
				void
			);

		DosHeader&
			getDosHeader(
				void
			);

		NtHeaders&
			getNtHeaders(
				void
			);

		SectionHeaders&
			getSectionHeaders(
				void
			);

		BaseObject&
			asBaseObject(
				void
			);

		SectionHeader&
			getSectionByVa(
				uint64_t va
			);

		SectionHeader&
			getSectionByRva(
				uint64_t rva
			);

		SectionHeader&
			getSectionByFo(
				uint64_t fo
			);

		//
		//	Pe read: enumerate data dictionary
		//

		using Exports = std::vector<std::tuple<uint32_t, std::string, void*>>;
		Exports
			enumExport(
				void
			);

		using Imports = std::vector<std::pair<std::string, std::vector<std::tuple<IMAGE_THUNK_DATA, std::string, WORD>>>>;
		Imports
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

		using Relocs = std::vector<std::pair<uint8_t, uint32_t>>;
		Relocs
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
		//	Pe write
		//

		bool
			rebuild(
				void
			);

		bool
			write(
				const std::filesystem::path& path
			);

		void
			write(
				Buffer& buffer
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
			);

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

		bool
			validVa(
				uint64_t va
			);

		bool
			validRva(
				uint64_t rva
			);

		bool
			validFo(
				uint64_t fo
			);

		virtual
			~Pe() = default;

	private:
		void
			open(
				void
			);
	};
}
