## TCP Scans

### Nmap scan for Common TCP ports
 
```
sudo nmap -sS -Pn -n -T4 -iL ips.txt -oA nmap-sS-common
```

### nmap scan for all / FULL TCP scan
```
sudo nmap -sS -Pn -n -T4 -p- -iL ips.txt -oA nmap-sS-allPorts
```

### Verify that found TCP ports are open
```
sudo nmap -sT -Pn -n -p <PORTS> -T4 -iL ips.txt -oA nmap-sT-verifyopen
```

### Detailed / Agressive Scan 
```
nmap -Pn -A -p <LIST> -iL ips.txt -oA detailednmap
```
 
## UDP SCANS

### Common UDP ports
```
nmap -sU -Pn -n -iL ips.txt -oA nmap-sU-common
```
 
```
nmap -sU -sC -sV -Pn -n -T2 -iL ips.txt -p <list> -oA nmap-sU-Scripts-openPorts
```

//TODO need to see specific commands to identify NetBIOS name etc.