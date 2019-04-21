#!/bin/bash
# Based on a test script from avsm/ocaml repo https://github.com/avsm/ocaml

CHROOT_DIR=/srv/arm-chroot
#TRAVIS_BUILD_DIR=~/git_stuff/drakvuf

sudo tar -xf ${TRAVIS_BUILD_DIR}/test-packages/arm-chroot.tar.gz -C /srv/
sudo cp /etc/resolv.conf ${CHROOT_DIR}/etc/resolv.conf
sudo mkdir -p ${CHROOT_DIR}/${TRAVIS_BUILD_DIR}
sudo rsync -a ${TRAVIS_BUILD_DIR}/ ${CHROOT_DIR}/${TRAVIS_BUILD_DIR}/

# Call ourselves again which will cause tests to run
sudo chroot ${CHROOT_DIR} bash -c "cd ${TRAVIS_BUILD_DIR} && ./travis-scripts/inside_chroot.sh"
