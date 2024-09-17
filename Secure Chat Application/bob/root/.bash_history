nano /etc/netplan/50-cloud-init.yaml
exit
route -n
apt install net-tools
route -n
exit
nslookup alice1
exit
exit
hostname
exit
ip a
ping 172.31.0.3
ping 172.31.0.2
ping 172.31.0.1
ping 172.31.0.3
ping 172.31.0.4
apt install traceroute
traceroute 172.31.0.2
ip a
tcpdump -i eth0
ping -c 1 172.31.0.2
ip a
ls
exit
ls
cd programs
ls
vim sec_server_client.cpp
g++ sec_server_client.cpp
g++ sec_server_client.cpp -lssl -lcrypto -o sec_cli
ls
./sec_cli -s
vim sec_server_client.cpp
g++ sec_server_client.cpp -lssl -lcrypto -o sec_cli
./sec_cli -s
exit
