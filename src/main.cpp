#include "oxlgr/pe_parser.hpp"
#include "oxlgr/report.hpp"

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_help() {
    std::cout << R"(OXLGR PE Sentinel
Analizador estatico defensivo de ejecutables Windows PE.

Autor: xtr4ng3-oxlgr
Etiqueta interna: xtr4ng3-oxlgr 🕷️

Uso:
  oxlgr-pe-sentinel <archivo.exe|archivo.dll> [opciones]

Opciones:
  --json <ruta>       Exportar reporte JSON
  --md <ruta>         Exportar reporte Markdown
  --max-strings <n>   Limite de strings indicadoras extraidas. Default: 300
  --help              Mostrar ayuda

Ejemplo:
  oxlgr-pe-sentinel suspicious.exe --json report.json --md report.md

Nota:
  Esta herramienta no ejecuta el archivo analizado. Solo lee bytes y estructuras PE.
)";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_help();
        return 2;
    }

    std::string target;
    std::string json_output;
    std::string md_output;
    std::size_t max_strings = 300;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }

        if (arg == "--json") {
            if (i + 1 >= argc) {
                std::cerr << "Falta ruta despues de --json\n";
                return 2;
            }
            json_output = argv[++i];
            continue;
        }

        if (arg == "--md") {
            if (i + 1 >= argc) {
                std::cerr << "Falta ruta despues de --md\n";
                return 2;
            }
            md_output = argv[++i];
            continue;
        }

        if (arg == "--max-strings") {
            if (i + 1 >= argc) {
                std::cerr << "Falta numero despues de --max-strings\n";
                return 2;
            }
            max_strings = static_cast<std::size_t>(std::stoul(argv[++i]));
            continue;
        }

        if (target.empty()) {
            target = arg;
        } else {
            std::cerr << "Argumento no reconocido: " << arg << "\n";
            return 2;
        }
    }

    if (target.empty()) {
        std::cerr << "Falta archivo objetivo.\n";
        return 2;
    }

    try {
        auto info = oxlgr::analyze_pe_file(target, max_strings);
        oxlgr::print_console_report(info);

        if (!json_output.empty()) {
            oxlgr::write_json_report(info, json_output);
            std::cout << "\nJSON exportado: " << json_output << "\n";
        }

        if (!md_output.empty()) {
            oxlgr::write_markdown_report(info, md_output);
            std::cout << "Markdown exportado: " << md_output << "\n";
        }

        return info.valid_pe ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
