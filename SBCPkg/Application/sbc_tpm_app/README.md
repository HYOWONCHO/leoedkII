

# SBC TPM2 Application Directory Structure

```text
project-root/
 ├─ CMakeLists.txt
 ├─ inc/                  # Header files
 │    ├─ tpm_example.h
 │    └─ tpm_version.h
 ├─ src/                  # Source files
 │    ├─ main.c
 │    ├─ tpm_example.c
 │    └─ tpm_version.c
 ├─ 3rdparty/             # Optional external dependencies
 └─ lib/                  # (Optional) build output
```


# SBC TPM2 Application Compile
## Build
Create directory:
```
mkdir build
cd build
```
Apply:
```
cmake ../
make
sudo make install
```

## Running without sudo 
Add user to "tss" group
```
sudo usermod -aG tss $USER
```
or add the udev rules (open access for all users)
Create file:
```
/etc/udev/rules.d/60-tpm.rules
```
Add:
```
KERNEL=="tpm[0-9]*", MODE="0666"
KERNEL=="tpmrm[0-9]*", MODE="0666"
```
Apply
```
sudo udevadm control --reload-rules
sudo udevadm trigger
```



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
```
### Fedora

libtool automake autoconf and autoconf-archive should be installed:
```
$ sudo dnf install libtool automake autoconf autoconf-archive
```
## Building From Source
### Bootstrapping the Build
To configure the tpm2-tss source code first run the bootstrap script, which
generates list of source files, and creates the configure script:
```
$ ./bootstrap
```

Any options specified to the bootstrap command are passed to `autoreconf(1)`.

### Configuring the Build
Then run the configure script, which generates the makefiles:
```
$ ./configure --prefix=/opt/sbc-tpm2-build
```









