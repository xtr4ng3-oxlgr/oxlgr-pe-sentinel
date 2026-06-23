# OXLGR PE Sentinel

**OXLGR PE Sentinel** es una herramienta corporativa de análisis estático defensivo para ejecutables Windows **PE** (`.exe`, `.dll`, `.sys`) escrita en **C++17**.

Fue diseñada para equipos de seguridad, analistas blue team, estudiantes avanzados, laboratorios de malware analysis, inventarios defensivos y procesos de triage donde se necesita una primera lectura técnica de un binario sin ejecutarlo.

**Autor:** `xtr4ng3-oxlgr`  
**Etiqueta interna:** `xtr4ng3-oxlgr 🕷️`  
**Licencia:** MIT  
**Estado:** gratuito, defensivo y abierto para la comunidad.

---

## Perfil ejecutivo

En análisis de binarios, el primer error suele ser ejecutar demasiado pronto.  
OXLGR PE Sentinel trabaja desde el principio opuesto: **leer, medir, clasificar y reportar antes de correr nada**.

La herramienta inspecciona la estructura PE directamente desde bytes, interpreta headers, secciones, imports, strings e indicadores de superficie defensiva. No intenta determinar “culpabilidad” del archivo. Su propósito es entregar una vista técnica sólida para que un analista pueda decidir qué merece una revisión más profunda.

El valor principal está en combinar varias señales en un reporte único:

- estructura PE,
- arquitectura,
- entry point,
- secciones y permisos,
- entropía global,
- entropía por sección,
- imports sensibles,
- strings indicadoras,
- presencia de overlay,
- mitigaciones básicas,
- hallazgos clasificados,
- score orientativo de riesgo.

Esto lo vuelve útil en entornos donde se necesita velocidad sin sacrificar criterio: revisión inicial de binarios desconocidos, triage de adjuntos sospechosos, clasificación interna, documentación de laboratorio, análisis académico o validación defensiva de software propio.

---

## Qué analiza

### Estructura PE

- DOS Header.
- NT Headers.
- Optional Header.
- Machine type.
- PE32 / PE32+.
- Entry Point RVA.
- Image Base.
- Subsystem.
- Number of sections.
- Size of image.
- Size of headers.
- DLL Characteristics.

### Secciones

Por cada sección:

- nombre,
- RVA,
- tamaño virtual,
- offset raw,
- tamaño raw,
- permisos `R/W/X`,
- entropía Shannon,
- secciones ejecutables y escribibles,
- secciones con datos virtuales sin raw data,
- secciones con entropía alta.

### Entropía

La entropía es uno de los ejes más importantes de la herramienta.

OXLGR PE Sentinel calcula:

- entropía global del archivo,
- entropía promedio de secciones,
- entropía individual por sección,
- entropía del overlay cuando existe.

Una entropía elevada no significa automáticamente malware. Puede indicar compresión, cifrado, empaquetado, recursos densos u ofuscación legítima. La herramienta lo trata como **señal defensiva**, no como condena.

### Imports

Extrae imports desde la Import Table y marca categorías relevantes:

- memoria,
- ejecución dinámica,
- procesos,
- hilos,
- red,
- registro,
- servicios,
- persistencia.

Ejemplos de APIs observadas como sensibles:

- `VirtualAlloc`
- `VirtualProtect`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `LoadLibraryA/W`
- `GetProcAddress`
- `CreateProcessA/W`
- `RegSetValueExA/W`
- `CreateServiceA/W`
- `InternetOpenA/W`
- `URLDownloadToFileA/W`
- `socket`
- `connect`

Estas APIs pueden ser completamente legítimas. El objetivo es que aparezcan en el reporte para acelerar el triage.

### Strings indicadoras

Extrae strings ASCII relevantes y las clasifica por contexto:

- URLs,
- comandos,
- referencias a PowerShell o CMD,
- rutas de persistencia,
- servicios externos,
- posibles tokens/webhooks,
- referencias a `.dll` o `.exe`.

### Overlay

Detecta datos anexados después de la imagen PE principal.

Un overlay puede ser normal en instaladores, firmas, empaquetadores o formatos híbridos. También puede ser relevante en análisis defensivo. Por eso la herramienta reporta:

- existencia,
- offset,
- tamaño,
- entropía.

---

## Qué NO hace

OXLGR PE Sentinel no es una herramienta ofensiva.

No hace:

- ejecución del binario,
- explotación,
- inyección,
- evasión,
- desempaquetado activo,
- conexión a internet,
- análisis dinámico,
- modificación del archivo,
- eliminación de archivos,
- clasificación automática como malware.

El reporte debe interpretarse con contexto.

---

## Compilar

### Linux / macOS / Windows con CMake

```bash
cmake -S . -B build
cmake --build build --config Release
```

### Windows con Visual Studio Developer Prompt

```bat
cmake -S . -B build
cmake --build build --config Release
```

El ejecutable queda en una ruta similar a:

```text
build/Release/oxlgr-pe-sentinel.exe
```

o:

```text
build/oxlgr-pe-sentinel
```

según el generador usado.

---

## Uso

```bash
oxlgr-pe-sentinel archivo.exe
```

Con reportes:

```bash
oxlgr-pe-sentinel archivo.exe --json report.json --md report.md
```

Limitar cantidad de strings:

```bash
oxlgr-pe-sentinel archivo.exe --max-strings 100
```

---

## Ejemplo de salida

```text
OXLGR PE Sentinel
Autor: xtr4ng3-oxlgr
Etiqueta interna: xtr4ng3-oxlgr 🕷️
------------------------------------------------------------
Archivo: sample.exe
Valido PE: si
Tamaño: 924672 bytes
Clase: PE32+
Arquitectura: x64
Subsistema: Windows GUI
EntryPoint RVA: 0x14000
ImageBase: 0x140000000
Secciones: 6
Imports: 142
Strings relevantes: 31
Entropia archivo: 6.873
Entropia media secciones: 5.921
Overlay: si (181248 bytes, entropia 7.611)
Puntaje de riesgo orientativo: 64/100
```

---

## Interpretación del score

El score es orientativo.

```text
0 - 25     Bajo interés inicial
26 - 50    Revisión recomendada
51 - 75    Triage defensivo prioritario
76 - 100   Alta densidad de señales
```

Un score alto no prueba que un archivo sea malicioso. Indica que el binario contiene suficientes señales estructurales para justificar una revisión más profunda.

---

## Estructura del proyecto

```text
oxlgr-pe-sentinel/
│
├─ CMakeLists.txt
├─ README.md
├─ LICENSE
├─ SECURITY.md
├─ CONTRIBUTING.md
├─ include/
│  └─ oxlgr/
│     ├─ byte_reader.hpp
│     ├─ entropy.hpp
│     ├─ indicators.hpp
│     ├─ pe_parser.hpp
│     ├─ report.hpp
│     ├─ strings.hpp
│     └─ types.hpp
├─ src/
│  ├─ main.cpp
│  ├─ entropy.cpp
│  ├─ indicators.cpp
│  ├─ pe_parser.cpp
│  ├─ report.cpp
│  └─ strings.cpp
├─ docs/
├─ examples/
├─ tests/
└─ .github/
   └─ workflows/
      └─ cmake.yml
```

---

## Uso responsable

Esta herramienta está pensada para análisis defensivo, aprendizaje, documentación y triage autorizado.  
No debe usarse para justificar acusaciones automáticas sobre un archivo ni para reemplazar análisis dinámico, sandboxing, firmas, telemetría o investigación humana.

---
---

## Licencia

MIT. Gratis para usar, estudiar, modificar y compartir.
