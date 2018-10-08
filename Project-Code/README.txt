-------------------------------------------------------------------------------------------------------------------------------
										SETTING UP RASPBERRY-PI AS OVS SWITCH
-------------------------------------------------------------------------------------------------------------------------------


The code given is divided into three phases
	
	1. Code to set up ovs on raspberry pi - ovs_setup.sh
	2. Prepare OVS configuration - ovs_prepare.sh
	3. Code to start ovs switch - ovs_switch.sh
	4. Remaining Configuration - ovs_prepare_rest.sh
	4. Code to add the required bridges and virtual network interfaces - ovs_prepare_rest.sh
	5. RYU code for entering flow entries

All these were done and experimented on our test bed. 


REFERENCE:

[1] xavier666. “Converting a Raspberry Pi to a OpenFlow Switch.” The Struggling Researcher, 17 June 2017, sumitrokgp.wordpress.com/2017/05/18/converting-a-raspberry-pi-to-a-openflow-switch/.


