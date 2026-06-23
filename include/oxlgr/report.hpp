#pragma once

#include <string>

#include "types.hpp"

namespace oxlgr {

void print_console_report(const PEInfo& info);
void write_markdown_report(const PEInfo& info, const std::string& path);
void write_json_report(const PEInfo& info, const std::string& path);

std::string json_escape(const std::string& input);

} // namespace oxlgr
