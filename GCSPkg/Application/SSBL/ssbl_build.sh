#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/../../../"

edit_file()
{
    local file="$1"
    local name="$2"

    if [ ! -f "$file" ]; then
        echo "[ERROR] $name not found: $file"
        exit 1
    fi

    echo "[INFO] Editing $name: $file"
    echo "[INFO] Save and quit (:wq) to continue..."
    sleep 1

    gedit "$file" || {
        echo "[ERROR] vi closed unexpectedly"
        exit 1
    }
}

while [ $# -gt 0 ]; do
    case "$1" in
        --inf)
            edit_file "$SCRIPT_DIR/SSBL.inf" "SSBL.inf"
            ;;

        --ver)
            edit_file "$ROOT_DIR/sbc_v.txt" "sbc_v.txt"
            ;;

        *)
            echo "[ERROR] Unknown option: $1"
            echo "Usage: $0 [--inf] [--ver]"
            exit 1
            ;;
    esac

    shift
done

pushd "$ROOT_DIR" > /dev/null || {
    echo "[ERROR] Failed to change directory to project root"
    exit 1
}

echo "[INFO] Building SSBL..."
./leo_build.sh --build-gcs-ssbl
ret=$?

popd > /dev/null || {
    echo "[ERROR] Failed to return to original directory"
    exit 1
}

exit $ret
