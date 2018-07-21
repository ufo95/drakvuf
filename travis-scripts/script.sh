#!/bin/bash
# Based on a test script from avsm/ocaml repo https://github.com/avsm/ocaml

CHROOT_DIR=/srv/arm-chroot
MIRROR=http://ftp2.de.debian.org/debian/
VERSION=sid
CHROOT_ARCH=arm64
#TRAVIS_BUILD_DIR=/home/uli/gsoc/mmomeu-stuff/drakvuf

echo ${TRAVIS_BUILD_DIR}/ ${CHROOT_DIR}/${TRAVIS_BUILD_DIR}/

# Debian package dependencies for the host
HOST_DEPENDENCIES="debootstrap qemu-user-static binfmt-support sbuild"

# Debian package dependencies for the chrooted environment
GUEST_DEPENDENCIES="build-essential git m4 sudo python bison flex automake aclocal autoconf autoconf-archive libtool libpython3.5-dev clang-3.8 libglib2.0-dev byacc git"

# Command used to run the tests
TEST_COMMAND="make test"

# Host dependencies
#sudo apt-get install -y ${HOST_DEPENDENCIES}

# Create chrooted environment
sudo mkdir ${CHROOT_DIR}
sudo debootstrap --foreign --no-check-gpg --include=fakeroot,build-essential \
    --arch=${CHROOT_ARCH} ${VERSION} ${CHROOT_DIR} ${MIRROR}
sudo cp /usr/bin/qemu-aarch64-static ${CHROOT_DIR}/usr/bin/
sudo chroot ${CHROOT_DIR} ./debootstrap/debootstrap --second-stage
sudo sbuild-createchroot --arch=${CHROOT_ARCH} --foreign --setup-only \
    ${VERSION} ${CHROOT_DIR} ${MIRROR}

# Create file with environment variables which will be used inside chrooted
# environment
echo "export ARCH=${ARCH}" > envvars.sh
echo "export TRAVIS_BUILD_DIR=${TRAVIS_BUILD_DIR}" >> envvars.sh
chmod a+x envvars.sh

# Install dependencies inside chroot
sudo chroot ${CHROOT_DIR} apt-get update
sudo chroot ${CHROOT_DIR} apt-get --allow-unauthenticated install \
    -y ${GUEST_DEPENDENCIES}

sudo mkdir -p ${CHROOT_DIR}/${TRAVIS_BUILD_DIR}
sudo rsync -a ${TRAVIS_BUILD_DIR}/ ${CHROOT_DIR}/${TRAVIS_BUILD_DIR}/

# Call ourselves again which will cause tests to run
sudo chroot ${CHROOT_DIR} bash -c "cd ${TRAVIS_BUILD_DIR} && ./travis-scripts/inside_chroot.sh"
