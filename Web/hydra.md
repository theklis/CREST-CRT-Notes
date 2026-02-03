## Hydra

### Basic Usage

**NOTE:** Capital `-L` allows specifying username list.
```
hydra -l <username> -P <password list> <target> <protocol> [options]
```

### Protocol Specific Usage

#### HTTP / HTTP-GET/POST

**NOTE:** The `login_failed_string` string used in example below is text that appears in the HTTP response when a login attempt **FAILS**.
```
hydra -l <username> -P <password list> <target> http-get /path
hydra -l admin -P /path/to/password_list.txt 127.0.0.1 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=login_failed_string"
```
#### FTP
```
hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100
```

#### SSH
```
hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100
```

#### Telnet
```
hydra -l <username> -P <password list> <target> telnet
```

#### RDP
```
hydra -l <username> -P <password list> <target> rdp
```

#### SMTP
```
hydra -l user@target.com -P passwords.txt smtp://target.com:587
hydra -L users.txt -P passwords.txt smtp://target.com:587
```