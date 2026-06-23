#pragma once

#include <set>
#include <string>

#include "types.hpp"

namespace oxlgr {

void evaluate_indicators(PEInfo& info);
int calculate_risk_score(const PEInfo& info);

bool is_sensitive_import(const std::string& name);
bool is_network_import(const std::string& name);
bool is_process_import(const std::string& name);
bool is_persistence_import(const std::string& name);

} // namespace oxlgr
