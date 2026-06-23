#include "oxlgr/indicators.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace oxlgr {

static std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool is_sensitive_import(const std::string& name) {
    static const std::set<std::string> names = {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "writeprocessmemory", "readprocessmemory", "createremotethread",
        "openprocess", "loadlibrarya", "loadlibraryw", "getprocaddress",
        "winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw",
        "ntqueryinformationprocess", "rtlmoveMemory", "queueuserapc"
    };
    return names.count(lower_copy(name)) > 0;
}

bool is_network_import(const std::string& name) {
    static const std::set<std::string> names = {
        "internetopena", "internetopenw", "internetconnecta", "internetconnectw",
        "internetreadfile", "httpopenrequesta", "httpopenrequestw",
        "httpsendrequesta", "httpsendrequestw", "urldownloadtofilea",
        "urldownloadtofilew", "wsastartup", "socket", "connect", "send", "recv",
        "winhttprequest", "winhttpopen", "winhttpconnect", "winhttpsendrequest"
    };
    return names.count(lower_copy(name)) > 0;
}

bool is_process_import(const std::string& name) {
    static const std::set<std::string> names = {
        "createprocessa", "createprocessw", "createthread", "createremotethread",
        "openprocess", "terminateprocess", "toolhelp32snapshot", "process32first",
        "process32next"
    };
    return names.count(lower_copy(name)) > 0;
}

bool is_persistence_import(const std::string& name) {
    static const std::set<std::string> names = {
        "regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw",
        "regopenkeyexa", "regopenkeyexw", "createservicea", "createservicew",
        "openscmanagera", "openscmanagerw", "startservicea", "startservicew"
    };
    return names.count(lower_copy(name)) > 0;
}

static void add_finding(
    PEInfo& info,
    const std::string& severity,
    const std::string& category,
    const std::string& title,
    const std::string& detail,
    const std::string& recommendation
) {
    info.findings.push_back(Finding{severity, category, title, detail, recommendation});
}

void evaluate_indicators(PEInfo& info) {
    if (!info.valid_pe) {
        add_finding(
            info,
            "alta",
            "formato",
            "Archivo PE inválido o incompleto",
            "No se pudo interpretar la estructura PE principal.",
            "Verificar que el archivo sea un ejecutable o DLL de Windows válido."
        );
        info.risk_score = calculate_risk_score(info);
        return;
    }

    if (info.file_entropy >= 7.2) {
        add_finding(
            info,
            "media",
            "entropia",
            "Entropía global elevada",
            "El archivo presenta una distribución de bytes compatible con compresión, empaquetado u ofuscación.",
            "Revisar secciones de alta entropía y confirmar si el binario usa empaquetadores legítimos."
        );
    }

    for (const auto& section : info.sections) {
        if (section.entropy >= 7.2) {
            add_finding(
                info,
                "media",
                "entropia",
                "Sección con entropía alta: " + section.name,
                "La sección registra entropía " + std::to_string(section.entropy) + ".",
                "Validar si la sección contiene datos comprimidos, cifrados, empaquetados o recursos legítimos."
            );
        }

        if (section.executable && section.writable) {
            add_finding(
                info,
                "alta",
                "permisos",
                "Sección ejecutable y escribible: " + section.name,
                "Una sección marcada como ejecutable y escribible incrementa el riesgo operacional.",
                "Revisar permisos de sección y proceso de compilación. RWX debe justificarse cuidadosamente."
            );
        }

        if (section.raw_size == 0 && section.virtual_size > 0) {
            add_finding(
                info,
                "baja",
                "seccion",
                "Sección virtual sin datos crudos: " + section.name,
                "La sección tiene tamaño virtual pero no posee datos crudos en el archivo.",
                "Revisar si corresponde a una sección normal de inicialización o reserva."
            );
        }
    }

    if (info.has_overlay) {
        std::string sev = info.overlay_entropy >= 7.2 ? "media" : "baja";
        add_finding(
            info,
            sev,
            "overlay",
            "Overlay detectado",
            "Se detectaron datos anexados después de la imagen PE. Tamaño: " + std::to_string(info.overlay_size) + " bytes.",
            "Revisar si el overlay corresponde a firma, instalador, empaquetador o datos agregados por terceros."
        );
    }

    int sensitive = 0;
    int network = 0;
    int process = 0;
    int persistence = 0;

    for (const auto& imp : info.imports) {
        if (is_sensitive_import(imp.name)) {
            ++sensitive;
        }
        if (is_network_import(imp.name)) {
            ++network;
        }
        if (is_process_import(imp.name)) {
            ++process;
        }
        if (is_persistence_import(imp.name)) {
            ++persistence;
        }
    }

    if (sensitive > 0) {
        add_finding(
            info,
            sensitive >= 8 ? "media" : "baja",
            "imports",
            "APIs sensibles importadas",
            "Se detectaron " + std::to_string(sensitive) + " imports asociados a memoria, procesos o ejecución dinámica.",
            "Analizar el contexto de uso. Estos imports pueden ser legítimos, pero son relevantes para triage defensivo."
        );
    }

    if (network > 0) {
        add_finding(
            info,
            "baja",
            "imports_red",
            "APIs de red importadas",
            "Se detectaron " + std::to_string(network) + " imports relacionados con comunicación de red.",
            "Correlacionar con strings, comportamiento esperado y documentación del software."
        );
    }

    if (process > 0) {
        add_finding(
            info,
            "baja",
            "imports_proceso",
            "APIs de proceso importadas",
            "Se detectaron " + std::to_string(process) + " imports relacionados con procesos o hilos.",
            "Revisar si el binario crea procesos, hilos o interactúa con otros procesos de forma esperada."
        );
    }

    if (persistence > 0) {
        add_finding(
            info,
            "media",
            "imports_persistencia",
            "APIs de persistencia o servicios importadas",
            "Se detectaron " + std::to_string(persistence) + " imports relacionados con registro o servicios.",
            "Confirmar si el software necesita instalar servicios, escribir claves de ejecución o modificar persistencia."
        );
    }

    std::map<std::string, int> string_categories;
    for (const auto& hit : info.strings) {
        ++string_categories[hit.category];
    }

    for (const auto& kv : string_categories) {
        if (kv.first == "secreto_o_credencial") {
            add_finding(
                info,
                "media",
                "strings",
                "Strings con posible material sensible",
                "Se detectaron " + std::to_string(kv.second) + " strings relacionadas con tokens, webhooks o autorización.",
                "Verificar que no existan secretos embebidos dentro del binario."
            );
        } else if (kv.first == "comando") {
            add_finding(
                info,
                "baja",
                "strings",
                "Strings de comandos o intérpretes",
                "Se detectaron " + std::to_string(kv.second) + " strings asociadas a comandos del sistema.",
                "Revisar si el binario invoca shell, PowerShell u otros intérpretes."
            );
        } else if (kv.first == "url") {
            add_finding(
                info,
                "baja",
                "strings",
                "URLs embebidas",
                "Se detectaron " + std::to_string(kv.second) + " URLs en strings.",
                "Validar dominios, endpoints y propósito de comunicación."
            );
        }
    }

    if ((info.dll_characteristics & 0x0040) == 0) {
        add_finding(
            info,
            "baja",
            "mitigaciones",
            "ASLR no aparece habilitado",
            "No se detectó IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.",
            "Compilar con mitigaciones modernas si el proyecto lo permite."
        );
    }

    if ((info.dll_characteristics & 0x0100) == 0) {
        add_finding(
            info,
            "baja",
            "mitigaciones",
            "NX/DEP no aparece habilitado",
            "No se detectó IMAGE_DLLCHARACTERISTICS_NX_COMPAT.",
            "Compilar con NX/DEP compatible para endurecer la superficie defensiva."
        );
    }

    info.risk_score = calculate_risk_score(info);
}

int calculate_risk_score(const PEInfo& info) {
    int score = 0;

    for (const auto& f : info.findings) {
        if (f.severity == "alta") {
            score += 22;
        } else if (f.severity == "media") {
            score += 12;
        } else if (f.severity == "baja") {
            score += 5;
        }
    }

    if (info.file_entropy >= 7.5) {
        score += 12;
    } else if (info.file_entropy >= 7.0) {
        score += 6;
    }

    if (info.has_overlay && info.overlay_size > 1024 * 512) {
        score += 7;
    }

    if (score > 100) {
        score = 100;
    }

    return score;
}

} // namespace oxlgr
