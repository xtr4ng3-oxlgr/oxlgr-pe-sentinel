#include "oxlgr/pe_parser.hpp"

#include "oxlgr/byte_reader.hpp"
#include "oxlgr/entropy.hpp"
#include "oxlgr/indicators.hpp"
#include "oxlgr/strings.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace oxlgr {

namespace {

constexpr std::uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr std::uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // PE\0\0

constexpr std::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr std::uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr std::uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

struct DataDirectory {
    std::uint32_t virtual_address;
    std::uint32_t size;
};

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("no se pudo abrir el archivo");
    }

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size < 0) {
        throw std::runtime_error("tamaño de archivo inválido");
    }

    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    return data;
}

std::string section_name_from_bytes(const std::vector<std::uint8_t>& data, std::size_t offset) {
    std::string name;
    for (std::size_t i = 0; i < 8 && offset + i < data.size(); ++i) {
        const char c = static_cast<char>(data[offset + i]);
        if (c == '\0') {
            break;
        }
        name.push_back(c);
    }
    if (name.empty()) {
        return "[sin_nombre]";
    }
    return name;
}

std::optional<std::uint32_t> rva_to_offset(const PEInfo& info, std::uint32_t rva) {
    for (const auto& section : info.sections) {
        const std::uint32_t start = section.virtual_address;
        const std::uint32_t span = std::max(section.virtual_size, section.raw_size);
        const std::uint32_t end = start + span;

        if (rva >= start && rva < end) {
            return section.raw_pointer + (rva - start);
        }
    }

    if (rva < info.size_of_headers) {
        return rva;
    }

    return std::nullopt;
}

void parse_imports(const ByteReader& br, PEInfo& info) {
    if (info.import_table_rva == 0 || info.import_table_size == 0) {
        return;
    }

    auto import_offset_opt = rva_to_offset(info, info.import_table_rva);
    if (!import_offset_opt) {
        return;
    }

    std::size_t desc_offset = *import_offset_opt;
    constexpr std::size_t descriptor_size = 20;
    int descriptor_guard = 0;

    while (br.can_read(desc_offset, descriptor_size) && descriptor_guard < 512) {
        const std::uint32_t original_first_thunk = br.read<std::uint32_t>(desc_offset + 0);
        const std::uint32_t time_date_stamp = br.read<std::uint32_t>(desc_offset + 4);
        const std::uint32_t forwarder_chain = br.read<std::uint32_t>(desc_offset + 8);
        const std::uint32_t name_rva = br.read<std::uint32_t>(desc_offset + 12);
        const std::uint32_t first_thunk = br.read<std::uint32_t>(desc_offset + 16);

        if (original_first_thunk == 0 && time_date_stamp == 0 && forwarder_chain == 0 && name_rva == 0 && first_thunk == 0) {
            break;
        }

        std::string dll = "[dll_desconocida]";
        if (auto name_offset = rva_to_offset(info, name_rva)) {
            dll = br.read_ascii(*name_offset, 256);
            if (dll.empty()) {
                dll = "[dll_desconocida]";
            }
        }

        const std::uint32_t thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
        auto thunk_offset_opt = rva_to_offset(info, thunk_rva);
        if (!thunk_offset_opt) {
            desc_offset += descriptor_size;
            ++descriptor_guard;
            continue;
        }

        std::size_t thunk_offset = *thunk_offset_opt;
        const bool is_pe64 = info.pe_class == "PE32+";
        int thunk_guard = 0;

        while (br.can_read(thunk_offset, is_pe64 ? 8 : 4) && thunk_guard < 4096) {
            std::uint64_t thunk = 0;
            if (is_pe64) {
                thunk = br.read<std::uint64_t>(thunk_offset);
            } else {
                thunk = br.read<std::uint32_t>(thunk_offset);
            }

            if (thunk == 0) {
                break;
            }

            ImportFunction imp;
            imp.dll = dll;

            const std::uint64_t ordinal_flag = is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL;
            if ((thunk & ordinal_flag) != 0) {
                imp.by_ordinal = true;
                imp.ordinal = static_cast<std::uint16_t>(thunk & 0xFFFF);
                imp.name = "ordinal_" + std::to_string(imp.ordinal);
            } else {
                const std::uint32_t hint_name_rva = static_cast<std::uint32_t>(thunk);
                if (auto hint_name_offset = rva_to_offset(info, hint_name_rva)) {
                    imp.ordinal = br.read<std::uint16_t>(*hint_name_offset);
                    imp.name = br.read_ascii(*hint_name_offset + 2, 512);
                }
            }

            if (!imp.name.empty()) {
                info.imports.push_back(imp);
            }

            thunk_offset += is_pe64 ? 8 : 4;
            ++thunk_guard;
        }

        desc_offset += descriptor_size;
        ++descriptor_guard;
    }
}

void detect_overlay(const std::vector<std::uint8_t>& data, PEInfo& info) {
    std::uint32_t end_of_image_on_disk = 0;

    for (const auto& section : info.sections) {
        const std::uint32_t end = section.raw_pointer + section.raw_size;
        if (end > end_of_image_on_disk) {
            end_of_image_on_disk = end;
        }
    }

    if (info.security_table_offset && info.security_table_size) {
        const std::uint32_t cert_end = info.security_table_offset + info.security_table_size;
        if (cert_end > end_of_image_on_disk) {
            end_of_image_on_disk = cert_end;
        }
    }

    if (end_of_image_on_disk < data.size()) {
        info.has_overlay = true;
        info.overlay_offset = end_of_image_on_disk;
        info.overlay_size = static_cast<std::uint32_t>(data.size() - end_of_image_on_disk);
        info.overlay_entropy = entropy_shannon(data, info.overlay_offset, info.overlay_size);
    }
}

} // namespace

std::string machine_to_string(std::uint16_t machine) {
    switch (machine) {
        case 0x014c: return "x86";
        case 0x8664: return "x64";
        case 0x01c0: return "ARM";
        case 0xaa64: return "ARM64";
        default: return "desconocida_0x" + std::to_string(machine);
    }
}

std::string subsystem_to_string(std::uint16_t subsystem) {
    switch (subsystem) {
        case 1: return "Native";
        case 2: return "Windows GUI";
        case 3: return "Windows Console";
        case 7: return "POSIX";
        case 9: return "Windows CE";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        default: return "desconocido_" + std::to_string(subsystem);
    }
}

PEInfo analyze_pe_file(const std::string& file_path, std::size_t max_strings) {
    PEInfo info;
    info.file_path = file_path;

    const auto data = read_file(file_path);
    info.file_size = data.size();
    info.file_entropy = entropy_shannon_full(data);
    info.sha256_like_note = "hash criptografico no calculado: esta version prioriza analisis estructural sin dependencias externas";

    ByteReader br(data);

    try {
        if (!br.can_read(0, 0x40)) {
            evaluate_indicators(info);
            return info;
        }

        const std::uint16_t mz = br.read<std::uint16_t>(0);
        if (mz != IMAGE_DOS_SIGNATURE) {
            evaluate_indicators(info);
            return info;
        }

        const std::uint32_t pe_offset = br.read<std::uint32_t>(0x3C);
        if (!br.can_read(pe_offset, 4 + 20)) {
            evaluate_indicators(info);
            return info;
        }

        const std::uint32_t pe_sig = br.read<std::uint32_t>(pe_offset);
        if (pe_sig != IMAGE_NT_SIGNATURE) {
            evaluate_indicators(info);
            return info;
        }

        const std::size_t file_header = pe_offset + 4;
        const std::uint16_t machine = br.read<std::uint16_t>(file_header + 0);
        info.number_of_sections = br.read<std::uint16_t>(file_header + 2);
        info.timestamp = br.read<std::uint32_t>(file_header + 4);
        const std::uint16_t optional_header_size = br.read<std::uint16_t>(file_header + 16);
        info.characteristics = br.read<std::uint16_t>(file_header + 18);

        const std::size_t optional = file_header + 20;
        if (!br.can_read(optional, optional_header_size)) {
            evaluate_indicators(info);
            return info;
        }

        const std::uint16_t magic = br.read<std::uint16_t>(optional);
        const bool is_pe32 = magic == 0x10b;
        const bool is_pe64 = magic == 0x20b;

        if (!is_pe32 && !is_pe64) {
            evaluate_indicators(info);
            return info;
        }

        info.valid_pe = true;
        info.pe_class = is_pe64 ? "PE32+" : "PE32";
        info.machine = machine_to_string(machine);

        info.entry_point_rva = br.read<std::uint32_t>(optional + 16);

        if (is_pe64) {
            info.image_base = br.read<std::uint64_t>(optional + 24);
            info.size_of_image = br.read<std::uint32_t>(optional + 56);
            info.size_of_headers = br.read<std::uint32_t>(optional + 60);
            info.subsystem = subsystem_to_string(br.read<std::uint16_t>(optional + 68));
            info.dll_characteristics = br.read<std::uint16_t>(optional + 70);

            const std::size_t dd = optional + 112;
            if (br.can_read(dd, 16 * 8)) {
                info.export_table_rva = br.read<std::uint32_t>(dd + 0 * 8);
                info.export_table_size = br.read<std::uint32_t>(dd + 0 * 8 + 4);
                info.import_table_rva = br.read<std::uint32_t>(dd + 1 * 8);
                info.import_table_size = br.read<std::uint32_t>(dd + 1 * 8 + 4);
                info.resource_table_rva = br.read<std::uint32_t>(dd + 2 * 8);
                info.resource_table_size = br.read<std::uint32_t>(dd + 2 * 8 + 4);
                info.security_table_offset = br.read<std::uint32_t>(dd + 4 * 8);
                info.security_table_size = br.read<std::uint32_t>(dd + 4 * 8 + 4);
            }
        } else {
            info.image_base = br.read<std::uint32_t>(optional + 28);
            info.size_of_image = br.read<std::uint32_t>(optional + 56);
            info.size_of_headers = br.read<std::uint32_t>(optional + 60);
            info.subsystem = subsystem_to_string(br.read<std::uint16_t>(optional + 68));
            info.dll_characteristics = br.read<std::uint16_t>(optional + 70);

            const std::size_t dd = optional + 96;
            if (br.can_read(dd, 16 * 8)) {
                info.export_table_rva = br.read<std::uint32_t>(dd + 0 * 8);
                info.export_table_size = br.read<std::uint32_t>(dd + 0 * 8 + 4);
                info.import_table_rva = br.read<std::uint32_t>(dd + 1 * 8);
                info.import_table_size = br.read<std::uint32_t>(dd + 1 * 8 + 4);
                info.resource_table_rva = br.read<std::uint32_t>(dd + 2 * 8);
                info.resource_table_size = br.read<std::uint32_t>(dd + 2 * 8 + 4);
                info.security_table_offset = br.read<std::uint32_t>(dd + 4 * 8);
                info.security_table_size = br.read<std::uint32_t>(dd + 4 * 8 + 4);
            }
        }

        const std::size_t section_table = optional + optional_header_size;
        constexpr std::size_t section_size = 40;

        double section_entropy_sum = 0.0;
        int entropy_count = 0;

        for (std::uint16_t i = 0; i < info.number_of_sections; ++i) {
            const std::size_t off = section_table + static_cast<std::size_t>(i) * section_size;
            if (!br.can_read(off, section_size)) {
                break;
            }

            SectionInfo sec;
            sec.name = section_name_from_bytes(data, off);
            sec.virtual_size = br.read<std::uint32_t>(off + 8);
            sec.virtual_address = br.read<std::uint32_t>(off + 12);
            sec.raw_size = br.read<std::uint32_t>(off + 16);
            sec.raw_pointer = br.read<std::uint32_t>(off + 20);
            sec.characteristics = br.read<std::uint32_t>(off + 36);
            sec.readable = (sec.characteristics & IMAGE_SCN_MEM_READ) != 0;
            sec.writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            sec.executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

            if (sec.raw_pointer < data.size() && sec.raw_size > 0) {
                const std::size_t available = std::min<std::size_t>(sec.raw_size, data.size() - sec.raw_pointer);
                sec.entropy = entropy_shannon(data, sec.raw_pointer, available);
                section_entropy_sum += sec.entropy;
                ++entropy_count;
            }

            info.sections.push_back(sec);
        }

        if (entropy_count > 0) {
            info.average_section_entropy = section_entropy_sum / static_cast<double>(entropy_count);
        }

        parse_imports(br, info);
        detect_overlay(data, info);
        info.strings = extract_interesting_strings(data, 5, max_strings);

    } catch (...) {
        // Si una lectura falla, se conserva la información parcial.
    }

    evaluate_indicators(info);
    return info;
}

} // namespace oxlgr
