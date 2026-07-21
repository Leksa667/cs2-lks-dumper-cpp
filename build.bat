@echo off
setlocal

where cmake >nul 2>&1
if errorlevel 1 (
    echo CMake not found. Install CMake 3.20+ and Visual Studio 2022 with C++ workload.
    exit /b 1
)

cmake -B build -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build build --config Release
if errorlevel 1 exit /b 1

echo.
echo Build complete: build\Release\cs2-lks-dumper.exe
exit /b 0
