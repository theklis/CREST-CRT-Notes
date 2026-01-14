## Network File System

### Recon

```
nmap -p 2049,111 target.com
```

### Share Enumeration

#### Using showmount

```
# List exported shares
showmount -e target.com

# List directories
showmount -d target.com

# List clients
showmount -a target.com
```

#### Using rpcinfo

```
# Using rpcinfo
rpcinfo -p target.com

# Manual RPC query
rpcinfo target.com | grep nfs
```

### Mounting and Exploring

```
# Mount share
mount -t nfs target.com:/share /mnt/nfs

# List contents
ls -la /mnt/nfs

# Find interesting files
find /mnt/nfs -type f -name "*.conf"
find /mnt/nfs -type f -name "*.key"
find /mnt/nfs -type f -name "*.pem"
find /mnt/nfs -type f -name "*password*"
find /mnt/nfs -type f -name "*.env"

# Search for credentials
grep -r "password\|secret\|key" /mnt/nfs

# Check permissions
ls -la /mnt/nfs
```

