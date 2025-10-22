#!/usr/bin/env bash


#set -euo pipefail


OF_DEV_NAME="/dev/nvme0n1p4"

usage() {
  cat <<'EOF'
    Usage: sbc_install.sh [options] [--] [args...]

    Options:
      --ssbl-copy[=FILENAME]        Copy the SSBL image in Bank of Raw Partition 
      --fsbl-copy[=FILENAME]        Copy the FSBL image in Bank of Raw Partition 
      --make-img[=FILENAME]         Add the header reagrd to File length
      -h, --help                    Help 

    Examples:
      ./getlongopt.sh -i in.bin --mode fast -v --threshold=7 extra1 extra2
      ./getlongopt.sh --input in.bin --output out.bin -- -filename-starts-with-dash
EOF
}


adding_length_in_image()
{
    #local _size=$(stat -c%s $1)

    #printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((size & 0xFF)) $(((size >> 8) & 0xFF)) $(((size >> 16) & 0xFF)) $(((size >> 24) & 0xFF)))" | cat - $1 > $2


    # 1. size를 리틀엔디언 4바이트(hex)로 변환
    local prefix=$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $((size & 0xFF)) \
        $(((size >> 8) & 0xFF)) \
        $(((size >> 16) & 0xFF)) \
        $(((size >> 24) & 0xFF)))

    # 2. 실제 바이트 데이터로 출력
    printf "$prefix" > header.bin

    # 3. header.bin + 원본 파일($1)을 합쳐서 새 파일($2)로 저장
    cat header.bin "$1" > "$2"

    # 4. 임시 파일 제거 (선택)
    rm -f header.bin


    #printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
    #    $((size & 0xFF)) \
    #    $(((size >> 8) & 0xFF)) \
    #    $(((size >> 16) & 0xFF)) \
    #    $(((size >> 24) & 0xFF)))" \
    #| cat - "$1" > "$2"

}

fsbl-img-copy_on_bank()
{
    local bnkid=$1
    local if_name=$2
    local of_name=$3
    local cpyaddr=$4

    #
    # If file does not exist, return 
    #
    
    [ -f $if_name ] || {printf "$if_name file not found"; return 1}
    [ -f $of_name ] || {printf "$of_name file not found"; return 1}

    local _seek=$(printf "%d" $cpyaddr)
    local _count=$(stat -c%s $if_name)

    printf "Write the FSBL Image in Bank $bnkid, Addr $_seek"

    $(which dd) if=$if_name of=$of_name seek=$_seek bs=1 count=$_count

}

ssbl-img-copy_on_bank()
{
    local bnkid=$1
    local if_name=$2
    local of_name=$3
    local cpyaddr=$4

    #
    # If file does not exist, return 
    #
    
    [ -f $if_name ] || {printf "$if_name file not found"; return 1}
    [ -f $of_name ] || {printf "$of_name file not found"; return 1}

    local _seek=$(printf "%d" $cpyaddr)
    local _count=$(stat -c%s $if_name)

    printf "Write the SSBL Image in Bank $bnkid, Addr $_seek"

    $(which dd) if=$if_name of=$of_name seek=$_seek bs=1 count=$_count

}


SHORT_OPTS="h"
LONG_OPTS="ssbl-copy::,fsbl-copy::,make-img::,help"

# parse
PARSED_OPTS="$(getopt -o "$SHORT_OPTS" -l "$LONG_OPTS" -n "$0" -- "$@")" || {
  printf "Try --help" >&2
  exit 2
}
# 파싱 결과를 셸 위치 매개변수로 재설정
eval set -- "$PARSED_OPTS"

# -----------------------------
# 옵션 해석 루프
# -----------------------------
while true; do
  case "$1" in
    -h|--help)
      usage; exit 0 ;;
    --ssbl-copy)
        case "$2" in
            ""|--) usage; shift 2 ;;
            * ) 
                ssbl-img-copy_on_bank 1 $2 $OF_DEV_NAME 0x400200
                sleep 1
                ssbl-img-copy_on_bank 2 $2 $OF_DEV_NAME 0x8400200
                sleep 1
                shift 2
                ;;
        esac
        ;;
    --fsbl-copy)
        case "$2" in
            ""|--) usage; shift 2 ;;
            * ) 
                fsbl-img-copy_on_bank 1 $2 $OF_DEV_NAME 0x200
                sleep 1
                fsbl-img-copy_on_bank 2 $2 $OF_DEV_NAME 0x8000200
                sleep 1
                shift 2
                ;;
        esac
        ;;
    --make-img)
        case "$2" in
            ""|--) usage; shift 2 ;;
            * ) 
                adding_length_in_image $2 $2.len
                shift 2
                ;;
        esac
        ;;
    --)
      shift; break ;;
    *)
      printf "Internal parsing error: $1" >&2
      exit 3 ;;
  esac
done

# -----------------------------
# 필수 인자 검증
# -----------------------------
#[[ -n "$INPUT" ]] || { printf "ERROR: --input is required"; printf; usage; exit 2; }
#[[ "$MODE" == "fast" || "$MODE" == "safe" ]] || {
#  printf "ERROR: --mode must be 'fast' or 'safe'"; exit 2;
#}

# 남은 일반 인자들 (옵션 이후)
REMAINING_ARGS=("$@")





