#!/bin/bash
set -e

# Clean build
if [ -d "build" ]; then
    echo "[INFO] Removing old build directory..."
    rm -rf build
fi

echo "[INFO] Creating fresh build directory..."
mkdir build
cd build

echo "[INFO] Running CMake..."
cmake ..

echo "[INFO] Building..."
make -j$(nproc)

echo "[OK] Build finished successfully!"
