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

		SectionHeader&
			getSectionByName(
				const std::string& name
			);

		//
		//	Pe read: enumerate data dictionary
		//

		typedef struct _EXPORT {
			uint32_t Ordinal;
			std::string Name;
			uint32_t Rva;
		} Export, * PExport;

		using Exports = std::vector<Export>;
		Exports
			enumExport(
				void
			);

		typedef struct _IMPORT {
			IMAGE_THUNK_DATA Thunk;
			struct
			{
				WORD Hint;
				std::string Name;
			} ByName;
		} Import, * PImport;

		using Imports = std::vector<Import>;
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

		typedef struct _RELOC {
			uint8_t Type;
			uint32_t Rva;
		} Reloc, * PReloc;

		using Relocs = std::vector<Reloc>;
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

		uint32_t
			computeChecksum(
				void
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
