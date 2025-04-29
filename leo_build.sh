#!/usr/bin/env bash

pkgname=none
module=none #"LeoTest/leo_test.inf"
build_flag=none

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

  build -p $pkg -t GCC5 -a X64


  #build -p $PackageName -t $Compiler -a $Architecture


}

function module_build()
{
  shift 1

  if [[ $(which build) == '' ]]; then
    echo "Setup the build environment"
    setup_env
  fi

  #pkgname="$1"
  #modulename="$2"



  pkg="${pkgname}/${pkgname}.dsc"
  #module="$2"

  if [[ ! -f ${pkg} ]]; then
    echo "Can not found the ${pkg} file" & exit
    exit
  fi

  if [[ ! -f ${module} ]]; then
    echo "Can not found the ${module} file" & exit
    exit
  fi

  build -p $pkg -t GCC5 -a X64 -m $module



}



declare -A long=([env-setup]=: \
                  [build-pkgX64]=: \
                  [build-moduleX64]=: \
                )

#echo "$@ - $#"
while _getopts_long long p:m:x opt "$@"; do
  case "$opt" in
    env-setup)
      setup_env
      ;;
    build-pkgX64)
      build_flag="pkgx64"
      #package_build
      ;;
    build-moduleX64)
      build_flag="modulex64"
      #module_build $@
      ;;
    p)
      #echo "-p : $OPTARG"
      pkgname=$OPTARG
      ;;
    m)
      #echo "-m : $OPTARG"
      module=$OPTARG
      ;;
    *)
      ;;
  esac
done


case "$build_flag" in
  pkgx64)
    package_build
    ;;
  modulex64)
    module_build
    ;;
  *)
    echo "Unknown options"
    ;;
esac


#declare -A long=([foo]=: [id]=: [silent]='')
#foo=none
#id=$USER


#silent=false
#while _getopts_long long f:i:sx opt "$@"; do
#shift $((OPTIND-1))
#echo "foo=$foo id=$id silent=$silent; args: $# $*"
#exit 0

