#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "types.hpp"

namespace oxlgr {

std::vector<StringHit> extract_interesting_strings(
    const std::vector<std::uint8_t>& data,
    std::size_t min_length,
    std::size_t max_results
);

std::string classify_string_indicator(const std::string& value);

} // namespace oxlgr
