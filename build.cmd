@echo off
rem Builds Caltrop.dll on Windows. Double-click this file, or run it from a terminal.
rem   1. Runs every test.  2. Builds the DLL.  3. Copies it into the "release" folder.
setlocal
cd /d "%~dp0"

rem Caltrop needs the .NET 10 SDK or newer.
dotnet --version >nul 2>nul
if errorlevel 1 (
  echo The .NET SDK is not installed. Get the .NET 10 SDK from https://dotnet.microsoft.com/download
  goto :failed
)
for /f "delims=" %%v in ('dotnet --version') do set "SDKVERSION=%%v"
for /f "delims=." %%m in ("%SDKVERSION%") do set /a SDKMAJOR=%%m 2>nul
if not defined SDKMAJOR set SDKMAJOR=0
if %SDKMAJOR% LSS 10 (
  echo Caltrop needs the .NET 10 SDK or newer, but this computer has %SDKVERSION%.
  echo Get it from https://dotnet.microsoft.com/download
  goto :failed
)

echo.
echo [1/3] Running the tests...
dotnet run --project tests\Caltrop.Tests --configuration Release
if errorlevel 1 (
  echo.
  echo Some tests FAILED, so no DLL was made. Scroll up to see which.
  goto :failed
)

echo.
echo [2/3] Building Caltrop.dll...
dotnet build src\Caltrop --configuration Release --nologo
if errorlevel 1 goto :failed

echo.
echo [3/3] Copying it into the release folder...
if not exist release mkdir release
copy /y artifacts\bin\Caltrop\release\Caltrop.dll release\ >nul
if errorlevel 1 goto :failed
copy /y artifacts\bin\Caltrop\release\Caltrop.xml release\ >nul

echo.
echo Done! Your DLL is here: %cd%\release\Caltrop.dll
echo.
echo Paste these two lines into your release notes:
for /f "delims=" %%h in ('certutil -hashfile release\Caltrop.dll SHA256 ^| findstr /v ":"') do echo SHA-256: %%h
echo Built with .NET SDK %SDKVERSION%
echo.
echo Anyone who builds this same source with that SDK gets the same SHA-256.
echo.
pause
exit /b 0

:failed
echo.
echo Build FAILED.
pause
exit /b 1
