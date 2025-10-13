#!/usr/bin/env bash

set -e


# Define colors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
NC='\e[0m' # No Color
pkgname=none
module=none #"LeoTest/leo_test.inf"
build_flag=none


fw_version=""
sat_baseanswr="sat-based-answer"

file="./sbc_v.txt"
declare -A VARS=()

# read key="value" lines safely
while IFS='=' read -r key val; do
    [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
    # trim leading/trailing spaces around key
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    # strip surrounding quotes from value and trim spaces
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    val="${val%\"}"; val="${val#\"}"
    VARS["$key"]="$val"
done < "$file"

major="${VARS[MAJOR_VAR]}"
minor="${VARS[MINOR_VAR]}"
patch="${VARS[PATCH_VAR]}"
pre="${VARS[PRERES_VAR]}"

if [[ -z "$pre" ]]; then
    fw_version="${major}.${minor}.${patch}"
else
    fw_version="${major}.${minor}.${patch}-${pre}"
fi


printf '%s\n' "$fw_version"


function _getopts_long {
  #if(($# < 3)); then
  #  printf 'Usage: options lvar optionstirng name [ARGS]n'
  #fi 1>&2

  [[ ${1:-} != lagrs ]] && local -n largs="$1"
  local optstr="$2"
  [[ ${3:-} != opt ]] && local -n opt="$3"
  local optvar="$3"

  shift 3

  OPTARG=
  : "${OPTIND}:=1"
  opt=${@:$OPTIND:1}
  if [[ $opt = -- ]]; then
    opt='?'
    return 1
  fi

  if [[ $opt = --* ]]; then
    local optval=false
    opt=${opt#--}
    if [[ $opt = *=* ]]; then
      OPTARG=${opt#*=}
      opt=${opt%%=* }
      optval=true
    fi
    ((++OPTIND))
    if [[ ${largs[$opt]+yes} != yes ]]; then
      ((OPTERR)) && printf 'bash: illegal long option %sn' "$opt" 1>&2
      return 0
    fi
    if [[ ${largs[$opt]:-} = : ]]; then
      if ! $optval; then
        OPTARG=${@:$OPTIND:1}
        ((++OPTIND))
      fi
    fi
    return 0
  fi

  getopts "$optstr" "$optvar" "$@"
}

function setup_env()
{
  . ./edk2_build_setup.sh
}

function package_build()
{

  shift 1

  #if [[ $# != 1 ]]; then
  #  echo " help : leo_build.sh --build-pkgX64 PackageName"
  #  exit
  #fi


  if [[ $(which build) == '' ]]; then
    echo "Setup the build environment"
    setup_env
  fi

  #pkgname="$1"
  pkg="${pkgname}/${pkgname}.dsc"

  if [[ ! -f ${pkg} ]]; then
    echo "Can not found the ${pkg} file" & exit
    exit
  fi

  echo $pkg

  build -p $pkg -t GCC5 -a X64 -b DEBUG -D DEBUG_ON_SERIAL_PORT=TRUE


  #build -p $PackageName -t $Compiler -a $Architecture


}


function post_copy_fsbl()
{
    echo -e "${YELLO}"
    pushd ./Build/SBC/DEBUG_GCC5/X64

    #printf "%-16s" ${sat_baseanswr} | tr ' ' '\0' >> FSBL.efi 
    #printf "%-16s" ${fw_version} | tr ' ' '\0' >> FSBL.efi 

    copyname="FSBL_$fw_version.efi"
    
    cp -i ./FSBL.efi ../../../../FwSignPy/.
    cp -i ./FSBL.efi ../../../../FwSignPy/$copyname
    popd
    echo -e "${NC}"
}

function post_copy_ssbl()
{
    echo -e "${YELLO}"
    pushd ./Build/SBC/DEBUG_GCC5/X64

    #printf "%-16s" ${sat_baseanswr} | tr ' ' '\0' >> SSBL.efi 
    #printf "%-16s" ${fw_version} | tr ' ' '\0' >> SSBL.efi 

    copyname="SSBL_$fw_version.efi"

    cp -i ./SSBL.efi ../../../../FwSignPy/.
    cp -i ./SSBL.efi ../../../../FwSignPy/$copyname
    popd
    echo -e "${NC}"
}



function module_build()
{
  echo "x1"
  #shift 1

  echo "x2"
  if [[ $(which build) == '' ]]; then
  echo "x3"
    echo "Setup the build environment"
    setup_env
  fi
  echo "x4"
  #pkgname="$1"
  #modulename="$2"



  echo "1"
  pkg="${pkgname}/${pkgname}.dsc"
  #module="$2"

  echo "2"
  if [[ ! -f ${pkg} ]]; then
    echo "Can not found the ${pkg} file" & exit
    exit
  fi

  echo "3"
  if [[ ! -f ${module} ]]; then
    echo "Can not found the ${module} file" & exit
    exit
  fi

  echo "4"
  build -p $pkg -t GCC5 -a X64 -m $module -b DEBUG -D DEBUG_ON_SERIAL_PORT=TRUE

  echo "5"
  local status=$?

  echo "6"
  if [ $status -eq 0 ]; then
      case "$module" in
        *FSBL*)
            echo  -e "${GREEN}Module build is done, Copy FSBL image ... ${NC}"
            post_copy_fsbl 
            ;;
        *SSBL*)
            echo  -e "${GREEN}Module build is done, Copy SSBL image ... ${NC}"
            post_copy_ssbl 
            ;;
        *)
            echo  -e "${RED} Invalid Module Name !!!${NC}" 
            ;;
      esac
  else
  echo "7"
      echo  -e "${RED}Module build Fails ${NC}" 
  fi


  echo "8"


}


declare -A long=([env-setup]=: \
                  [build-pkgX64]=: \
                  [build-moduleX64]=: \
                  [build-ssbl]=: \
                  [build-fsbl]=: \
                )

echo "$@ - $#"
while _getopts_long long p:m:x opt "$@"; do
  case "$opt" in
    env-setup)
        echo "setup_env"
      setup_env
      ;;
    build-pkgX64)
        echo "build-pkgX64"
      build_flag="pkgx64"
      package_build
      #package_build
      ;;
    build-moduleX64)
        echo "build-moduleX64"
      build_flag="modulex64"
      module_build
      #module_build $@
      ;;
    build-ssbl)
        echo "build-ssbl"
        pkgname="SBCPkg"
        echo "build-ssbl-1"
        module="SBCPkg/Application/SSBL/SSBL.inf"
        echo "build-ssbl-2"
        module_build
        echo "build-ssbl-3"
        ;;
    build-fsbl)
        echo "build-fsbl"
        pkgname="SBCPkg"
        module="SBCPkg/Application/FSBL/FSBL.inf"
        module_build
        ;;
    p)
      echo "-p : $OPTARG"
      pkgname=$OPTARG
      ;;
    m)
      echo "-m : $OPTARG"
      module=$OPTARG
      ;;
    *)
      ;;
  esac
done


#case "$build_flag" in
#  pkgx64)
#      package_build
#      ;;
#  modulex64)
#      module_build
#      ;;
#  *)
#    echo "Unknown options"
#    ;;
#esac


#declare -A long=([foo]=: [id]=: [silent]='')
#foo=none
#id=$USER


#silent=false
#while _getopts_long long f:i:sx opt "$@"; do
#shift $((OPTIND-1))
#echo "foo=$foo id=$id silent=$silent; args: $# $*"
#exit 0

