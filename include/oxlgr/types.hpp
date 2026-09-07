#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace oxlgr {

// OXLGR PE Sentinel
// Autor: xtr4ng3-oxlgr
// Etiqueta interna: xtr4ng3-oxlgr 🕷️
// Herramienta defensiva de análisis estático. No ejecuta el binario analizado.

struct SectionInfo {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_pointer = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

struct ImportFunction {
    std::string dll;
    std::string name;
    std::uint16_t ordinal = 0;
    bool by_ordinal = false;
};

struct StringHit {
    std::string value;
    std::size_t offset = 0;
    std::string category;
};

struct Finding {
    std::string severity;
    std::string category;
    std::string title;
    std::string detail;
    std::string recommendation;
};

struct PEInfo {
    std::string file_path;
    std::uintmax_t file_size = 0;
    std::string sha256_like_note;
    bool valid_pe = false;

    std::string pe_class;
    std::string machine;
    std::string subsystem;

    std::uint32_t timestamp = 0;
    std::uint16_t number_of_sections = 0;
    std::uint32_t entry_point_rva = 0;
    std::uint64_t image_base = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t characteristics = 0;
    std::uint16_t dll_characteristics = 0;

    std::uint32_t import_table_rva = 0;
    std::uint32_t import_table_size = 0;
    std::uint32_t export_table_rva = 0;
    std::uint32_t export_table_size = 0;
    std::uint32_t resource_table_rva = 0;
    std::uint32_t resource_table_size = 0;
    std::uint32_t security_table_offset = 0;
    std::uint32_t security_table_size = 0;

    bool has_overlay = false;
    std::uint32_t overlay_offset = 0;
    std::uint32_t overlay_size = 0;
    double overlay_entropy = 0.0;

    double file_entropy = 0.0;
    double average_section_entropy = 0.0;

    std::vector<SectionInfo> sections;
    std::vector<ImportFunction> imports;
    std::vector<StringHit> strings;
    std::vector<Finding> findings;

    int risk_score = 0;
};

} // namespace oxlgr
