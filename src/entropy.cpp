#include "oxlgr/entropy.hpp"

#include <array>
#include <cmath>
#include <algorithm>

namespace oxlgr {

double entropy_shannon(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t size) {
    if (data.empty() || size == 0 || offset >= data.size()) {
        return 0.0;
    }

    const std::size_t end = std::min(data.size(), offset + size);
    const std::size_t actual = end - offset;
    if (actual == 0) {
        return 0.0;
    }

    std::array<std::size_t, 256> freq{};
    for (std::size_t i = offset; i < end; ++i) {
        ++freq[data[i]];
    }

    double entropy = 0.0;
    for (std::size_t count : freq) {
        if (count == 0) {
            continue;
        }

        const double p = static_cast<double>(count) / static_cast<double>(actual);
        entropy -= p * std::log2(p);
    }

    return entropy;
}

double entropy_shannon_full(const std::vector<std::uint8_t>& data) {
    return entropy_shannon(data, 0, data.size());
}

} // namespace oxlgr
