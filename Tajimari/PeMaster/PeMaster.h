#pragma once
#define NOMINMAX
#include <filesystem>
#include <vector>
#include <windows.h>

#include "DosHeader.h"
#include "NtHeaders.h"
#include "SectionHeader.h"

//
//  These macros are used to test, set and clear flags respectivly
//

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

namespace PeMaster {
	class Pe
		:virtual public BaseObject,
		private DosHeader,
		private NtHeaders,
		private SectionHeaders
	{
	public:
		explicit
			Pe() = default;

		explicit
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
				size_t va
			);

		SectionHeader&
			getSectionByRva(
				size_t rva
			);

		SectionHeader&
			getSectionByFo(
				size_t fo
			);

		SectionHeader&
			getSectionByName(
				const std::string& name
			);

		//
		//	Pe read: enumerate data dictionary
		//

		using Export = struct _EXPORT {
			uint32_t Ordinal = 0;
			std::string Name;
			uint32_t Rva = 0;
		};

		using Exports = std::vector<Export>;
		Exports
			enumExport(
				void
			);

		using Import = struct _IMPORT {
			size_t Ordinal;
			struct
			{
				WORD Hint = 0;
				std::string Name;
			} ByName;
		};

		using ImportEntry = struct _IMPORT_ENTRY {
			std::string DllName;
			DWORD TimeDateStamp = 0;
			DWORD ForwarderChain = 0;
			std::vector<Import> Iat;
			std::vector<Import> Ilt;
		};

		using Imports = std::vector<ImportEntry>;
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

		using Reloc = struct _RELOC {
			uint8_t Type = 0;
			uint32_t Rva = 0;
		};

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

		void
			setImport(
				Imports& imports
			);

		size_t
			updateHeaders(
				void
			);

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

		size_t
			vaToRva(
				size_t va
			);

		size_t
			rvaToVa(
				size_t rva
			);

		size_t
			foToRva(
				size_t fo
			);

		size_t
			rvaToFo(
				size_t rva
			);

		size_t
			foToVa(
				size_t fo
			);

		size_t
			vaToFo(
				size_t va
			);

		bool
			validVa(
				size_t va
			);

		bool
			validRva(
				size_t rva
			);

		bool
			validFo(
				size_t fo
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
