# Network Enumeration

## Host Discovery

### Fping
```
fping -a -g -q 10.10.10.0/24 | tee ips.txt
```

### Nmap Ping Scan
```
nmap -sn 192.168.1.0/24
```

### Nmap ARP Ping (local networks)
```
nmap -PR 192.168.1.0/24
```

### ARP-Scan (local, reliable)
```
sudo arp-scan -I eth0 10.10.10.0/24
```

### NetDiscover(passive)
```
sudo netdiscover -r 10.10.10.0/24
```

### Massscan (fast, local ranges)
```
masscan 10.0.0.0/24
```



## TCP Port Scanning

### Nmap scan for Common TCP ports
 
```
sudo nmap -sS -Pn -n -T4 -iL ips.txt -oA nmap-sS-common
```

### nmap scan for all / FULL TCP scan
```
sudo nmap -sS -Pn -n -T4 -p- -iL ips.txt -oA nmap-sS-allPorts
```

### Verify Open TCP Ports (3-way handshake)
```
sudo nmap -sT -Pn -n -p <PORTS> -T4 -iL ips.txt -oA nmap-sT-verifyopen
```

### Detailed / Aggressive Scan (services, scripts, OS) 
```
nmap -Pn -A -p <LIST> -iL ips.txt -oA detailednmap
```
 
## UDP Port Scanning

### Common UDP ports
```
nmap -sU -Pn -n -iL ips.txt -oA nmap-sU-common
```

### UDP Scripts & Version Detection (confirmed ports)
```
nmap -sU -sC -sV -Pn -n -T2 -iL ips.txt -p <list> -oA nmap-sU-Scripts-openPorts
```


## OS Fingerprinting

### nmap OS Detection

```
nmap -O 10.10.10.1
```

### TTL Inspection
```
ping 10.10.10.1
```
* Windows = 128
* Linux = 64
* Cisco = 255

### p0f (passive OS Fingerprinting)
```
p0f -i <network_interface>
```


## Internet Information Gathering and Reconnaissance

### Nslookup

#### Resolve a given hostname to the corresponding IP
```
nslookup target.com
```

#### Reverse DNS lookup
```
nslookup -type=PTR IP_address
```

#### MX (Mail Exchange) lookup
```
nslookup -type=MX domain.com
```

### DNSRecon

#### Performing General Enumeration against target
```
dnsrecon -d domain.com -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml 
```
#### DNS reverse of all of the addresses
```
dnsrecon -r  127.0.0.0/24 -n  <IP_DNS> 
dnsrecon -r  127.0.1.0/24 -n  <IP_DNS>
dnsrecon -r  <IP_DNS>/24 -n  <IP_DNS>
```

### Dig
```
dig ANY @<DNS_IP> <DOMAIN>     #Any information

dig A @<DNS_IP> <DOMAIN>       #Regular DNS request

dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request

dig TXT @<DNS_IP> <DOMAIN>     #Information

dig MX @<DNS_IP> <DOMAIN>      #Emails related

dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name

dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup

dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup
```

### Zone Transfer

#### Dig
```
dig axfr @<DNS_IP> <DOMAIN> 
```

#### DNSRecon
```
dnsrecon -d active.htb -a  -n  <IP_DNS> 
```

## Network Connection
### Telnet
```
telnet 10.10.10.10 21
```

## VLAN Tagging
