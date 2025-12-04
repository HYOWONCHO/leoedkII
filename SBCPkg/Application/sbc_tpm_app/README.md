# 3rdparty TPM2-TSS Library Compile

## Dependency 
To build and install the tpm2-tss software the following softare packages are required. 

## GNU/Linux
  * GNU Autoconf
  * GNU Autoconf Archive, version >= 2019.01.06
  * GNU Automake
  * GNU Libtool
  * C compiler
  * C library development libraries and header files
  * pkg-config
  * doxygen
  * OpenSSL development libraries and header files, version >= 1.1.0
  * libcurl development libraries
  * Access Control List utility (acl)
  * JSON C Development library
  * Package libusb-1.0-0-dev


  The following are dependencies only required when building test suites.
  * Integration test suite (see ./configure option --enable-integration):
      + uthash development libraries and header files
      + ps executable (usually in the procps package)
      + ss executable (usually in the iproute2 package)
      + tpm_server executable (from https://sourceforge.net/projects/ibmswtpm2/)
  * Unit test suite (see ./configure option --enable-unit):
      + cmocka unit test framework, version >= 1.0
  * Code coverage analysis:
      + lcov

  Most users will not need to install these dependencies.

### Ubuntu
``````
```
$ sudo apt -y update
$ sudo apt -y install \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  procps \
  iproute2 \
  build-essential \
  git \
  pkg-config \
  gcc \
  libtool \
  automake \
  libssl-dev \
  uthash-dev \
  autoconf \
  doxygen \
  libjson-c-dev \
  libini-config-dev \
  libcurl4-openssl-dev \
  uuid-dev \
  libltdl-dev \
  libusb-1.0-0-dev \
  libftdi-dev
``````
``








