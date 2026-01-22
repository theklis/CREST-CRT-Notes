## Attacking Web Apps with ffuf

### Enumerate dirs
```
ffuf -u http://[IP]/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

ffuf -u http://[IP]/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -fs <size of request to filter out>

ffuf  -u http://SERVER_IP:PORT/blog/FUZZ.php  -w wordlist.txt

ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v

ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/

ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H'Host: FUZZ.academy.htb' -fs xxx


```

### Wordlists

```
# Directory/Page Wordlist
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
Directory/PageWordlist

# Extensions Wordlist
/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
ExtensionsWordlist

# Domain Wordlist
/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
Domain Wordlist

# Parameters Wordlist
/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
```