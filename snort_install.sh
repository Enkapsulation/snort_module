#!/bin/bash

PATH_SNORT_DIR_LIB=~/Desktop/snort_lib
PATH_SNORT_DIR=~/Desktop/Snort3
PATH_EXTRA_PLUGIN=~/Desktop/Snort3_extra
SNORT_VERSION=3.1.17.0

# Create folder for tar balls 
mkdir -p ${PATH_SNORT_DIR_LIB}
cd ${PATH_SNORT_DIR_LIB}

#  Install snort3 Presqueties
sudo apt-get install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev \
zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev openssl libssl-dev cpputest libsqlite3-dev \
libtool uuid-dev git autoconf bison flex libcmocka-dev libnetfilter-queue-dev libunwind-dev \
libmnl-dev ethtool

# Download and install safec
cd ${PATH_SNORT_DIR_LIB}
wget https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
tar -xzvf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure
make
sudo make install

# Install PCRE
cd ${PATH_SNORT_DIR_LIB}
wget wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
tar -xzvf pcre-8.45.tar.gz
cd pcre-8.45
./configure
make
sudo make install

# install gperftools
cd ${PATH_SNORT_DIR_LIB}
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar -xzvf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1
./configure
make
sudo make install

# install ragel
cd ${PATH_SNORT_DIR_LIB}
wget http://www.colm.net/files/ragel/ragel-6.10.tar.gz
tar -xzvf ragel-6.10.tar.gz
cd ragel-6.10
./configure
make
sudo make install

# download Boost
cd ${PATH_SNORT_DIR_LIB}
wget https://boostorg.jfrog.io/artifactory/main/release/1.77.0/source/boost_1_77_0.tar.gz
tar -xvzf boost_1_77_0.tar.gz

# install Hyperscan
cd ${PATH_SNORT_DIR_LIB}
wget https://github.com/intel/hyperscan/archive/refs/tags/v5.4.0.tar.gz
tar -xvzf v5.4.0.tar.gz
mkdir -p ${PATH_SNORT_DIR_LIB}/hyperscan-5.4.0-build
cd hyperscan-5.4.0-build/
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBOOST_ROOT=${PATH_SNORT_DIR_LIB}/boost_1_77_0/ ../hyperscan-5.4.0
make
sudo make install

# install flatbuffers
cd ${PATH_SNORT_DIR_LIB}
wget https://github.com/google/flatbuffers/archive/refs/tags/v2.0.0.tar.gz -O flatbuffers-v2.0.0.tar.gz
tar -xzvf flatbuffers-v2.0.0.tar.gz
mkdir flatbuffers-build
cd flatbuffers-build
cmake ../flatbuffers-2.0.0
make
sudo make install

# isntall daq
cd ${PATH_SNORT_DIR_LIB}
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
tar -xzvf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5
./bootstrap
./configure
make
sudo make install

# Update shares libraries
sudo ldconfig

# install snort
mkdir ${PATH_SNORT_DIR}
cd ${PATH_SNORT_DIR}
wget https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz -O snort3-${SNORT_VERSION}.tar.gz
tar -xzvf snort3-${SNORT_VERSION}.tar.gz
cd snort3-${SNORT_VERSION}
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make
sudo make install

# Check installation process
/usr/local/bin/snort -V

#  Test Snort with default configuration
snort -c /usr/local/etc/snort/snort.lua

# Download and install snort_extra
cd ~/Desktop
wget https://github.com/snort3/snort3_extra/archive/refs/tags/3.1.17.0.tar.gz -O snort3_extra-3.1.17.0.tar.gz
tar -xzvf snort3_extra-3.1.17.0.tar.gz
cd snort3_extra-3.1.17.0/
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/
./configure_cmake.sh --prefix=/usr/local
cd build
make
sudo make install
