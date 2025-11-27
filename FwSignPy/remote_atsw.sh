#!/bin/bash

# ==========================================
# Color
# ==========================================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
NC="\033[0m" # no color

# ==========================================
# Usage
# ==========================================
print_usage() {
    echo -e "\nUsage:"
    echo -e "  $0 <host> <script_path> [VAR=value] [--log logname]"
    echo -e "\nExamples:"
    echo -e "  $0 user@host \"/opt/run.sh -opt\" VAR=1"
    echo -e "  $0 root@192.168.0.10 /tmp/build.sh --log fsbl"
    echo -e "\nOptions:"
    echo -e "  --log         Custom log file name (without extension)"
    echo -e "  --help        Show this help"
    echo ""
}

# ==========================================
# Parse Args
# ==========================================
if [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

HOST="$1"
SCRIPT="$2"
VAR=""
LOG_NAME="remote_run"

if [ "$3" != "" ] && [[ "$3" == *=* ]]; then
    VAR="$3"
elif [ "$3" = "--log" ]; then
    LOG_NAME="$4"
fi

# if log name set by positional 4
if [ "$4" = "--log" ]; then
    LOG_NAME="$5"
fi


# ==========================================
# Check Args
# ==========================================
if [ -z "$HOST" ] || [ -z "$SCRIPT" ]; then
    print_usage
    exit 1
fi


# ==========================================
# Generate log filename
# ==========================================
DATETIME=$(date +%Y%m%d_%H%M%S)
LOGFILE="${LOG_NAME}_${DATETIME}.log"


# ==========================================
# Prepare Remote Command
# ==========================================
if [ -n "$VAR" ]; then
    REMOTE_CMD="$VAR $SCRIPT"
else
    REMOTE_CMD="$SCRIPT"
fi

# Check script exist on remote
SSH_CHECK="test -f \"$SCRIPT\""
ssh "$HOST" "$SSH_CHECK"
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Remote script not found: $SCRIPT${NC}"
    exit 1
fi

echo -e "${YELLOW}[INFO] Executing:${NC} $REMOTE_CMD"
sleep 1


# ==========================================
# Execute
# ==========================================
ssh -t "$HOST" "$REMOTE_CMD" 2>&1 | tee "$LOGFILE"
RET=${PIPESTATUS[0]}


# ==========================================
# Result Message
# ==========================================
if [ $RET -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Log saved → $LOGFILE"
else
    echo -e "${RED}[FAILED]${NC} Log saved → $LOGFILE"
fi

exit $RET

