#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "types.hpp"

namespace oxlgr {

PEInfo analyze_pe_file(
    const std::string& file_path,
    std::size_t max_strings = 300
);

std::string machine_to_string(std::uint16_t machine);
std::string subsystem_to_string(std::uint16_t subsystem);

} // namespace oxlgr
