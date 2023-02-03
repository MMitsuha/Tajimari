#pragma once
#include <vector>
#include <spdlog/spdlog.h>
#include <filesystem>

namespace PeMaster {
	class BaseObject
	{
	public:
		BaseObject() = default;

		BaseObject(
			const std::filesystem::path& path
		);

		virtual
			bool
			open(
				const std::filesystem::path& path
			);

		virtual
			void
			open(
				const std::vector<uint8_t>& buffer
			);

		virtual
			~BaseObject() = default;

	protected:
		std::vector<uint8_t> m_buffer;
		bool m_valid = false;

	private:
		void
			copyFrom(
				void const* pointer,
				size_t size
			);
	};
}
