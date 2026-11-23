#!/usr/bin/env bash
# Builds Caltrop.dll on macOS or Linux. Run it with: bash build.sh
#   1. Runs every test.  2. Builds the DLL.  3. Copies it into the "release" folder.
set -euo pipefail
cd "$(dirname "$0")"

# Caltrop needs the .NET 10 SDK or newer.
version="$(dotnet --version 2>/dev/null || true)"
major="${version%%.*}"
if [[ -z "$version" || ! "$major" =~ ^[0-9]+$ ]]; then
  echo "The .NET SDK is not installed. Get the .NET 10 SDK from https://dotnet.microsoft.com/download"
  exit 1
fi
if (( major < 10 )); then
  echo "Caltrop needs the .NET 10 SDK or newer, but this computer has $version."
  echo "Get it from https://dotnet.microsoft.com/download"
  exit 1
fi

echo
echo "[1/3] Running the tests..."
if ! dotnet run --project tests/Caltrop.Tests --configuration Release; then
  echo
  echo "Some tests FAILED, so no DLL was made. Scroll up to see which."
  exit 1
fi

echo
echo "[2/3] Building Caltrop.dll..."
dotnet build src/Caltrop --configuration Release --nologo

echo
echo "[3/3] Copying it into the release folder..."
mkdir -p release
cp artifacts/bin/Caltrop/release/Caltrop.dll artifacts/bin/Caltrop/release/Caltrop.xml release/

echo
echo "Done! Your DLL is here: $(pwd)/release/Caltrop.dll"
echo
if command -v sha256sum >/dev/null 2>&1; then
  hash="$(sha256sum release/Caltrop.dll | cut -d' ' -f1)"
else
  hash="$(shasum -a 256 release/Caltrop.dll | cut -d' ' -f1)"
fi
echo "Paste these two lines into your release notes:"
echo "SHA-256: $hash"
echo "Built with .NET SDK $version"
echo
echo "Anyone who builds this same source with that SDK gets the same SHA-256."
