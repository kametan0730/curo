# curo
curo = curonos - nos

curo is a software router

## Functions

### Interface

- [x] Raw socket with PF_PACKET
- [ ] DPDK(Data Plane Development Kit)

### Network
- [x] ARP Reply
- [x] ARP Request
- [x] Unlimited IP Routing Table
- [x] IP Forwarding
- [x] ICMP Echo Reply
- [x] ICMP Time Exceeded
- [x] ICMP Destination Unreachable
- [x] NAT (UDP,TCP,ICMP(Query))
- [ ] NAT (ICMP(Error))

## Build
```shell
sudo apt install build-essential
git clone https://github.com/kametan0730/curo.git
cd curo
make all
```

## Example
### 0. Download sources and build

### 1. Create environment with network namespace
```shell
ip netns add host1
ip netns add router1
ip netns add router2
ip netns add host2

ip link add name host1-router1 type veth peer name router1-host1
ip link add name router1-router2 type veth peer name router2-router1
ip link add name router2-host2 type veth peer name host2-router2

ip link set host1-router1 netns host1
ip link set router1-host1 netns router1
ip link set router1-router2 netns router1
ip link set router2-router1 netns router2
ip link set router2-host2 netns router2
ip link set host2-router2 netns host2

ip netns exec host1 ip addr add 192.168.1.2/24 dev host1-router1
ip netns exec host1 ip link set host1-router1 up
ip netns exec host1 ethtool -K host1-router1 rx off tx off
ip netns exec host1 ip route add default via 192.168.1.1

ip netns exec router1 ip link set router1-host1 up
ip netns exec router1 ethtool -K router1-host1 rx off tx off
ip netns exec router1 ip link set router1-router2 up
ip netns exec router1 ethtool -K router1-router2 rx off tx off

ip netns exec router2 ip addr add 192.168.0.2/24 dev router2-router1
ip netns exec router2 ip link set router2-router1 up
ip netns exec router2 ethtool -K router2-router1 rx off tx off
ip netns exec router2 ip route add default via 192.168.0.1
ip netns exec router2 ip addr add 192.168.2.1/24 dev router2-host2
ip netns exec router2 ip link set router2-host2 up
ip netns exec router2 ethtool -K router2-host2 rx off tx off
ip netns exec router2 sysctl -w net.ipv4.ip_forward=1

ip netns exec host2 ip addr add 192.168.2.2/24 dev host2-router2
ip netns exec host2 ip link set host2-router2 up
ip netns exec host2 ethtool -K host2-router2 rx off tx off
ip netns exec host2 ip route add default via 192.168.2.1
```

### 2. Config
#### Open main.cpp and change configure function as follows
```cpp
void configure(){
    configure_ip_address(get_net_device_by_name("router1-host1"), IP_ADDRESS(192, 168, 1, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip(get_net_device_by_name("router1-router2"), IP_ADDRESS(192, 168, 0, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip_net_route(IP_ADDRESS(192, 168, 2, 0), 24, IP_ADDRESS(192, 168, 0, 2));
}
```

## 3. Execute
### 3.1 Join router1 namespace
```shell
sudo ip netns exec router1 bash
```

### 3.2 Move the directory to where curo is located

### 3.3 Execute
```shell
make run
```

## 4. Enjoy!
### Ready two terminals
```shell
sudo ip netns exec host1 iperf3 -s
```
```shell
sudo ip netns exec host2 iperf3 -c 192.168.1.2
```
