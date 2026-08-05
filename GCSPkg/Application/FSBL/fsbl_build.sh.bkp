#!/bin/bash

# If --inf option is given → edit SSBL.inf
if [ "$1" = "--inf" ]; then
    INF_FILE="./FSBL.inf" 

    if [ ! -f "$INF_FILE" ]; then
        echo "[ERROR] SSBL.inf not found: $INF_FILE"
        exit 1
    fi

    echo "[INFO] Editing SSBL INF file: $INF_FILE"
    echo "[INFO] Save and quit (:wq) to continue..."
    sleep 1

    vi "$INF_FILE" || {
        echo "[ERROR] vi closed unexpectedly"
        exit 1
    }
fi

# Build FSBL
pushd "$(dirname "$0")/../../../" > /dev/null || {
    echo "[ERROR] Failed to change directory to project root"
    exit 1
}

echo "[INFO] Building FSBL..."
./leo_build.sh --build-fsbl
ret=$?

popd > /dev/null || {
    echo "[ERROR] Failed to return to original directory"
    exit 1
}

exit $ret

