#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oxlgr {

double entropy_shannon(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t size);
double entropy_shannon_full(const std::vector<std::uint8_t>& data);

} // namespace oxlgr
