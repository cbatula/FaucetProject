ip route del 192.168.128.0/24 dev ens38
ip route del 192.168.128.0/24 dev ens39
ip route del 192.168.128.0/24 dev ens40
ip route add 192.168.128.100/32 dev ens38
ip route add 192.168.128.110/32 dev ens39
ip route add 192.168.128.111/32 dev ens40
