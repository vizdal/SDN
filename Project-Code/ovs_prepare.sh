# Gain super user permission
sudo su
# Move to datapath directory and turn on OVS
cd openvswitch-2.5.2/datapath/linux
modprobe openvswitch
#To create ovs start up code
sudo nano ovs-switch.sh