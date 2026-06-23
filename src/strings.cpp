#include "oxlgr/strings.hpp"

#include <algorithm>
#include <cctype>
#include <set>

namespace oxlgr {

static std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string classify_string_indicator(const std::string& value) {
    const std::string v = lower_copy(value);

    if (v.find("http://") != std::string::npos || v.find("https://") != std::string::npos) {
        return "url";
    }
    if (v.find("powershell") != std::string::npos || v.find("cmd.exe") != std::string::npos ||
        v.find("rundll32") != std::string::npos || v.find("regsvr32") != std::string::npos) {
        return "comando";
    }
    if (v.find("appdata") != std::string::npos || v.find("\\startup") != std::string::npos ||
        v.find("currentversion\\run") != std::string::npos) {
        return "persistencia";
    }
    if (v.find("webhook") != std::string::npos || v.find("token") != std::string::npos ||
        v.find("authorization:") != std::string::npos || v.find("bearer ") != std::string::npos) {
        return "secreto_o_credencial";
    }
    if (v.find("discord") != std::string::npos || v.find("telegram") != std::string::npos ||
        v.find("pastebin") != std::string::npos) {
        return "servicio_externo";
    }
    if (v.find(".dll") != std::string::npos || v.find(".exe") != std::string::npos) {
        return "referencia_binaria";
    }

    return {};
}

std::vector<StringHit> extract_interesting_strings(
    const std::vector<std::uint8_t>& data,
    std::size_t min_length,
    std::size_t max_results
) {
    std::vector<StringHit> hits;
    std::string current;
    std::size_t start = 0;

    auto flush = [&](std::size_t end_offset) {
        if (current.size() >= min_length) {
            const std::string category = classify_string_indicator(current);
            if (!category.empty()) {
                hits.push_back(StringHit{current, start, category});
            }
        }
        current.clear();
        start = end_offset;
    };

    for (std::size_t i = 0; i < data.size(); ++i) {
        const unsigned char c = data[i];
        if (c >= 32 && c <= 126) {
            if (current.empty()) {
                start = i;
            }
            current.push_back(static_cast<char>(c));
        } else {
            flush(i + 1);
            if (hits.size() >= max_results) {
                return hits;
            }
        }
    }

    flush(data.size());

    if (hits.size() > max_results) {
        hits.resize(max_results);
    }

    return hits;
}

} // namespace oxlgr
