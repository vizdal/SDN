#!/bin/sh

# Gain Super user permission
sudo su
#To download OpenVSwitch - Wused 2.9.2 Version
wget http://openvswitch.org/releases/openvswitch-2.9.2.tar.gz
#un-pack archive file 
tar -xvzf openvswitch-2.9.2.tar.gz
echo Installing Requirements
apt-get install python-simplejson python-qt4 libssl-dev python-twisted-conch automake autoconf gcc uml-utilities libtool build-essential pkg-config
apt-get install raspberrypi-kernel-headers
#entering  ovs folder
cd openvswitch-2.9.2
#make and install ovs
./configure
make
make install
echo Instalation Completed!