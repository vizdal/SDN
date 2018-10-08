sudo su
touch /usr/local/etc/ovs-vswitchd.conf
mkdir -p /usr/local/etc/openvswitch
./openvswitch-2.9.2/ovsdb/ovsdb-tool create /usr/local/etc/openvswitch/conf.db /root/openvswitch-2.9.2/vswitchd/vswitch.ovsschema
sh ovs_script.sh
# Create a bridge
ovs-vsctl add-br br0
# Add a virtual interface
ip link add veth1 type veth
ifconfig veth1 up
# Add interfaces to bridge
ovs-vsctl add-port br0 eth0
ovs-vsctl add-port br0 veth1
ovs-vsctl add-port br0 wlan0
# Assign Controller value
ovs-vsctl set-controller br0 tcp:134.151.131.220:6633
ovs-vsctl show