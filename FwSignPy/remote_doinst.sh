#!/bin/bash

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; NC="\033[0m"

print_usage() {
    echo -e "\nUsage:"
    echo -e "  $0 <host> <script_path> <device> <ipaddr> [--log name]"
    echo -e "\nExample:"
    echo -e "  $0 user@host /usr/bin/do_inst /dev/nvme0n1p4 192.168.122.134"
    echo -e "  $0 user@host /usr/bin/do_inst /dev/nvme0n1p4 192.168.122.134 --log install"
    echo ""
}

# Help
[[ "$1" = "--help" ]] && { print_usage; exit 0; }

HOST="$1"
SCRIPT="$2"
DEV="$3"
IPADDR="$4"
LOG_NAME="remote_run"

if [[ -z "$HOST" || -z "$SCRIPT" || -z "$DEV" || -z "$IPADDR" ]]; then
    print_usage
    exit 1
fi

shift 4

# Optional: log name
if [[ "$1" = "--log" ]]; then
    LOG_NAME="$2"
fi

DATETIME=$(date +%Y%m%d_%H%M%S)
LOGFILE="${LOG_NAME}_${DATETIME}.log"

# Validate remote script
SSH_CHECK="command -v $SCRIPT >/dev/null 2>&1 || test -f \"$SCRIPT\""
ssh "$HOST" "$SSH_CHECK"
if [[ $? -ne 0 ]]; then
    echo -e "${RED}[ERROR] Script not found on remote: $SCRIPT${NC}"
    exit 1
fi

REMOTE_CMD="$SCRIPT $DEV $IPADDR"

echo -e "${YELLOW}[INFO] Exec: ${NC}$REMOTE_CMD"
sleep 1

ssh -t "$HOST" "$REMOTE_CMD" 2>&1 | tee "$LOGFILE"
RET=${PIPESTATUS[0]}

if [[ $RET -eq 0 ]]; then
    echo -e "${GREEN}[SUCCESS]${NC} log saved → $LOGFILE"
else
    echo -e "${RED}[FAILED]${NC} log saved → $LOGFILE"
fi

exit $RET

