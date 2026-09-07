#include "oxlgr/report.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace oxlgr {

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (char c : input) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 32) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

static std::string bool_text(bool value) {
    return value ? "si" : "no";
}

void print_console_report(const PEInfo& info) {
    std::cout << "\nOXLGR PE Sentinel\n";
    std::cout << "Autor: xtr4ng3-oxlgr\n";
    std::cout << "Etiqueta interna: xtr4ng3-oxlgr 🕷️\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << "Archivo: " << info.file_path << "\n";
    std::cout << "Valido PE: " << bool_text(info.valid_pe) << "\n";
    std::cout << "Tamaño: " << info.file_size << " bytes\n";

    if (info.valid_pe) {
        std::cout << "Clase: " << info.pe_class << "\n";
        std::cout << "Arquitectura: " << info.machine << "\n";
        std::cout << "Subsistema: " << info.subsystem << "\n";
        std::cout << "EntryPoint RVA: 0x" << std::hex << info.entry_point_rva << std::dec << "\n";
        std::cout << "ImageBase: 0x" << std::hex << info.image_base << std::dec << "\n";
        std::cout << "Secciones: " << info.sections.size() << "\n";
        std::cout << "Imports: " << info.imports.size() << "\n";
        std::cout << "Strings relevantes: " << info.strings.size() << "\n";
        std::cout << "Entropia archivo: " << std::fixed << std::setprecision(3) << info.file_entropy << "\n";
        std::cout << "Entropia media secciones: " << std::fixed << std::setprecision(3) << info.average_section_entropy << "\n";
        std::cout << "Overlay: " << bool_text(info.has_overlay);
        if (info.has_overlay) {
            std::cout << " (" << info.overlay_size << " bytes, entropia " << std::fixed << std::setprecision(3) << info.overlay_entropy << ")";
        }
        std::cout << "\n";
    }

    std::cout << "Puntaje de riesgo orientativo: " << info.risk_score << "/100\n";
    std::cout << "------------------------------------------------------------\n";

    if (!info.sections.empty()) {
        std::cout << "\n[Secciones]\n";
        for (const auto& s : info.sections) {
            std::cout << "- " << s.name
                      << " RVA=0x" << std::hex << s.virtual_address
                      << " RAW=0x" << s.raw_pointer
                      << std::dec
                      << " size=" << s.raw_size
                      << " entropy=" << std::fixed << std::setprecision(3) << s.entropy
                      << " flags=" << (s.readable ? "R" : "-") << (s.writable ? "W" : "-") << (s.executable ? "X" : "-")
                      << "\n";
        }
    }

    if (!info.findings.empty()) {
        std::cout << "\n[Hallazgos]\n";
        for (const auto& f : info.findings) {
            std::cout << "[" << f.severity << "] " << f.title << "\n";
            std::cout << "  Categoria: " << f.category << "\n";
            std::cout << "  Detalle: " << f.detail << "\n";
            std::cout << "  Recomendacion: " << f.recommendation << "\n";
        }
    }
}

void write_markdown_report(const PEInfo& info, const std::string& path) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("no se pudo escribir reporte markdown");
    }

    out << "# OXLGR PE Sentinel — Reporte defensivo\n\n";
    out << "- Autor: **xtr4ng3-oxlgr**\n";
    out << "- Etiqueta interna: `xtr4ng3-oxlgr 🕷️`\n";
    out << "- Archivo: `" << info.file_path << "`\n";
    out << "- Tamaño: `" << info.file_size << " bytes`\n";
    out << "- PE válido: **" << bool_text(info.valid_pe) << "**\n";
    out << "- Puntaje de riesgo orientativo: **" << info.risk_score << "/100**\n\n";

    if (info.valid_pe) {
        out << "## Perfil ejecutivo\n\n";
        out << "| Campo | Valor |\n|---|---|\n";
        out << "| Clase | `" << info.pe_class << "` |\n";
        out << "| Arquitectura | `" << info.machine << "` |\n";
        out << "| Subsistema | `" << info.subsystem << "` |\n";
        out << "| EntryPoint RVA | `0x" << std::hex << info.entry_point_rva << std::dec << "` |\n";
        out << "| ImageBase | `0x" << std::hex << info.image_base << std::dec << "` |\n";
        out << "| Secciones | `" << info.sections.size() << "` |\n";
        out << "| Imports | `" << info.imports.size() << "` |\n";
        out << "| Strings relevantes | `" << info.strings.size() << "` |\n";
        out << "| Entropía global | `" << std::fixed << std::setprecision(3) << info.file_entropy << "` |\n";
        out << "| Entropía media secciones | `" << std::fixed << std::setprecision(3) << info.average_section_entropy << "` |\n";
        out << "| Overlay | `" << bool_text(info.has_overlay) << "` |\n\n";
    }

    out << "## Hallazgos\n\n";
    if (info.findings.empty()) {
        out << "No se registraron hallazgos relevantes.\n\n";
    } else {
        out << "| Severidad | Categoría | Hallazgo | Recomendación |\n|---|---|---|---|\n";
        for (const auto& f : info.findings) {
            out << "| " << f.severity << " | " << f.category << " | "
                << f.title << " — " << f.detail << " | "
                << f.recommendation << " |\n";
        }
        out << "\n";
    }

    out << "## Secciones\n\n";
    out << "| Nombre | RVA | Raw | Tamaño raw | Entropía | Permisos |\n|---|---:|---:|---:|---:|---|\n";
    for (const auto& s : info.sections) {
        out << "| `" << s.name << "` | `0x" << std::hex << s.virtual_address
            << "` | `0x" << s.raw_pointer << std::dec
            << "` | " << s.raw_size
            << " | " << std::fixed << std::setprecision(3) << s.entropy
            << " | " << (s.readable ? "R" : "-") << (s.writable ? "W" : "-") << (s.executable ? "X" : "-") << " |\n";
    }

    out << "\n## Imports relevantes\n\n";
    if (info.imports.empty()) {
        out << "No se registraron imports o no se pudo interpretar la tabla.\n\n";
    } else {
        out << "| DLL | Función |\n|---|---|\n";
        std::size_t limit = 200;
        for (std::size_t i = 0; i < info.imports.size() && i < limit; ++i) {
            out << "| `" << info.imports[i].dll << "` | `" << info.imports[i].name << "` |\n";
        }
        if (info.imports.size() > limit) {
            out << "\n_Lista truncada a " << limit << " imports._\n";
        }
    }

    out << "\n## Strings indicadoras\n\n";
    if (info.strings.empty()) {
        out << "No se detectaron strings indicadoras en el límite configurado.\n\n";
    } else {
        out << "| Offset | Categoría | Valor |\n|---:|---|---|\n";
        for (const auto& s : info.strings) {
            out << "| `0x" << std::hex << s.offset << std::dec << "` | " << s.category << " | `" << s.value << "` |\n";
        }
    }

    out << "\n## Nota de uso responsable\n\n";
    out << "Este reporte es de análisis estático defensivo. No determina por sí solo si un binario es malicioso. "
           "Los hallazgos deben interpretarse con contexto, procedencia del archivo y comportamiento esperado.\n";
}

void write_json_report(const PEInfo& info, const std::string& path) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("no se pudo escribir reporte json");
    }

    out << "{\n";
    out << "  \"tool\": \"OXLGR PE Sentinel\",\n";
    out << "  \"author\": \"xtr4ng3-oxlgr\",\n";
    out << "  \"tag\": \"xtr4ng3-oxlgr 🕷️\",\n";
    out << "  \"file_path\": \"" << json_escape(info.file_path) << "\",\n";
    out << "  \"file_size\": " << info.file_size << ",\n";
    out << "  \"valid_pe\": " << (info.valid_pe ? "true" : "false") << ",\n";
    out << "  \"pe_class\": \"" << json_escape(info.pe_class) << "\",\n";
    out << "  \"machine\": \"" << json_escape(info.machine) << "\",\n";
    out << "  \"subsystem\": \"" << json_escape(info.subsystem) << "\",\n";
    out << "  \"entry_point_rva\": " << info.entry_point_rva << ",\n";
    out << "  \"image_base\": " << info.image_base << ",\n";
    out << "  \"file_entropy\": " << std::fixed << std::setprecision(6) << info.file_entropy << ",\n";
    out << "  \"average_section_entropy\": " << std::fixed << std::setprecision(6) << info.average_section_entropy << ",\n";
    out << "  \"has_overlay\": " << (info.has_overlay ? "true" : "false") << ",\n";
    out << "  \"overlay_offset\": " << info.overlay_offset << ",\n";
    out << "  \"overlay_size\": " << info.overlay_size << ",\n";
    out << "  \"overlay_entropy\": " << std::fixed << std::setprecision(6) << info.overlay_entropy << ",\n";
    out << "  \"risk_score\": " << info.risk_score << ",\n";

    out << "  \"sections\": [\n";
    for (std::size_t i = 0; i < info.sections.size(); ++i) {
        const auto& s = info.sections[i];
        out << "    {"
            << "\"name\":\"" << json_escape(s.name) << "\","
            << "\"virtual_address\":" << s.virtual_address << ","
            << "\"virtual_size\":" << s.virtual_size << ","
            << "\"raw_pointer\":" << s.raw_pointer << ","
            << "\"raw_size\":" << s.raw_size << ","
            << "\"entropy\":" << std::fixed << std::setprecision(6) << s.entropy << ","
            << "\"readable\":" << (s.readable ? "true" : "false") << ","
            << "\"writable\":" << (s.writable ? "true" : "false") << ","
            << "\"executable\":" << (s.executable ? "true" : "false")
            << "}";
        if (i + 1 < info.sections.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"findings\": [\n";
    for (std::size_t i = 0; i < info.findings.size(); ++i) {
        const auto& f = info.findings[i];
        out << "    {"
            << "\"severity\":\"" << json_escape(f.severity) << "\","
            << "\"category\":\"" << json_escape(f.category) << "\","
            << "\"title\":\"" << json_escape(f.title) << "\","
            << "\"detail\":\"" << json_escape(f.detail) << "\","
            << "\"recommendation\":\"" << json_escape(f.recommendation) << "\""
            << "}";
        if (i + 1 < info.findings.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"imports\": [\n";
    for (std::size_t i = 0; i < info.imports.size(); ++i) {
        const auto& imp = info.imports[i];
        out << "    {"
            << "\"dll\":\"" << json_escape(imp.dll) << "\","
            << "\"name\":\"" << json_escape(imp.name) << "\","
            << "\"ordinal\":" << imp.ordinal << ","
            << "\"by_ordinal\":" << (imp.by_ordinal ? "true" : "false")
            << "}";
        if (i + 1 < info.imports.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"strings\": [\n";
    for (std::size_t i = 0; i < info.strings.size(); ++i) {
        const auto& s = info.strings[i];
        out << "    {"
            << "\"offset\":" << s.offset << ","
            << "\"category\":\"" << json_escape(s.category) << "\","
            << "\"value\":\"" << json_escape(s.value) << "\""
            << "}";
        if (i + 1 < info.strings.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

} // namespace oxlgr
