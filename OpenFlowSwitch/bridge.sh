ovs-vsctl del-br main
ovs-vsctl add-br main
ifconfig main up
ovs-vsctl set bridge main other-config:datapath-id=0000000000000001
ovs-vsctl add-port main ens33
ifconfig ens33 0
ovs-vsctl add-port main ens39 -- add-port main ens40
ovs-vsctl set-controller main tcp:192.168.128.100:6654 tcp:192.168.128.100:6653
