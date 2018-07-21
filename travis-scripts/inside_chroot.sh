#!/bin/bash

apt update
apt install -y make autoconf autoconf-archive git libtool pkg-config libglib2.0-dev bison flex libjson-c-dev clang libvirt-dev cmake
# for xen-arm:
#apt install -y python-dev gettext iasl uuid-dev libpixman-1-dev ftp libyajl-dev libfdt-dev

echo $PWD
#install prebuild xen
dpkg -i test-packages/xen_1-1_arm64.deb

#build & install libvmi
#git submodule update --init libvmi
#cd libvmi/
#echo $PWD
cd ..
git clone https://github.com/libvmi/libvmi.git
cd libvmi

mkdir build
cd build
cmake ..
make -j3

cd ../drakvuf
#build drakvuf
#export CXX="clang++-3.8"
autoreconf -vi
./configure --disable-plugin-poolmon --disable-plugin-filetracer --disable-plugin-filedelete --disable-plugin-objmon --disable-plugin-exmon --disable-plugin-ssdtmon --disable-plugin-debugmon --disable-plugin-cpuidmon --disable-plugin-socketmon --disable-plugin-regmon --disable-plugin-procmon
make -j3
