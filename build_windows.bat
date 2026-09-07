@echo off
title OXLGR PE Sentinel - Build Windows
color 0B
cd /d "%~dp0"

echo ============================================================
echo OXLGR PE Sentinel - Build Windows
echo xtr4ng3-oxlgr
echo ============================================================
echo.

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo No se encontro CMake.
    echo Instala CMake o usa Visual Studio con herramientas C++.
    pause
    exit /b
)

cmake -S . -B build
cmake --build build --config Release

echo.
echo Build terminado.
echo Revisar build\Release\oxlgr-pe-sentinel.exe o build\oxlgr-pe-sentinel.exe
pause
