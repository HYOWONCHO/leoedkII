#!/bin/bash

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; NC="\033[0m"

print_usage() {
    echo -e "\nUsage:"
    echo -e "  $0 <host> <command> [args ...] [--log name] [--nosudo]"
    echo -e "\nExamples:"
    echo -e "  $0 user@host ls -l /root --log listroot"
    echo -e "  $0 user@host hexdump -C /dev/nvme0n1p4 --nosudo"
    echo -e "  $0 user@host /root/do_inst /dev/nvme0n1p4 192.168.122.134 --log install"
    echo ""
}

[[ "$1" = "--help" ]] && { print_usage; exit 0; }

HOST="$1"
shift

CMD="$1"
shift

if [[ -z "$HOST" || -z "$CMD" ]]; then
    print_usage
    exit 1
fi

LOG_NAME="remote_run"
USE_SUDO=true

USER_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log)
            LOG_NAME="$2"
            shift 2
            ;;
        --nosudo)
            USE_SUDO=false
            shift 1
            ;;
        *)
            USER_ARGS+=("$1")
            shift 1
            ;;
    esac
done

APP_ARGS="${USER_ARGS[*]}"

DATETIME=$(date +%Y%m%d_%H%M%S)
LOGFILE="${LOG_NAME}_${DATETIME}.log"

if $USE_SUDO; then
    REMOTE_CMD="sudo $CMD $APP_ARGS"
else
    REMOTE_CMD="$CMD $APP_ARGS"
fi

echo -e "${YELLOW}[INFO] Exec:${NC} $REMOTE_CMD"

ssh -t "$HOST" "$REMOTE_CMD" 2>&1 | tee "$LOGFILE"
RET=${PIPESTATUS[0]}

if [[ $RET -eq 0 ]]; then
    echo -e "${GREEN}[SUCCESS]${NC} Log → $LOGFILE"
else
    echo -e "${RED}[FAILED]${NC} Log → $LOGFILE"
fi

exit $RET

