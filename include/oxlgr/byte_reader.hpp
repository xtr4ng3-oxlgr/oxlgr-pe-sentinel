#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace oxlgr {

class ByteReader {
public:
    explicit ByteReader(const std::vector<std::uint8_t>& data) : data_(data) {}

    std::size_t size() const {
        return data_.size();
    }

    bool can_read(std::size_t offset, std::size_t count) const {
        return offset <= data_.size() && count <= data_.size() - offset;
    }

    template <typename T>
    T read(std::size_t offset) const {
        if (!can_read(offset, sizeof(T))) {
            throw std::runtime_error("lectura fuera de rango");
        }
        T value{};
        std::memcpy(&value, data_.data() + offset, sizeof(T));
        return value;
    }

    std::string read_ascii(std::size_t offset, std::size_t max_len) const {
        if (offset >= data_.size()) {
            return {};
        }

        std::string out;
        for (std::size_t i = offset; i < data_.size() && out.size() < max_len; ++i) {
            char c = static_cast<char>(data_[i]);
            if (c == '\0') {
                break;
            }
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                break;
            }
            out.push_back(c);
        }
        return out;
    }

    const std::vector<std::uint8_t>& bytes() const {
        return data_;
    }

private:
    const std::vector<std::uint8_t>& data_;
};

} // namespace oxlgr
