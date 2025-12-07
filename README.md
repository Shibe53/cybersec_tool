# 2IC80 Tool for Attacks

A custom tool that offers a selection of customizable attacks to use. This can be found in the folder 'tool'.

## How to run the ARP Poisoning (WIP)

1. Put the file 'arp_poisoning.py' on the attacker machine.

2. Run it using `python3 arp.py` (make sure scapy is installed).

3. Input the interface (e.g., eth0), victim IP, and the website/router's IP.

## CyberSec Network Testing Environment

A Docker-based setup for cybersecurity testing with three interconnected containers. This can be found in the folder 'network'.

## System Description

This environment creates a private network with four containers:
- **Victim**: Alpine Linux container that sends HTTP requests
- **Attacker**: Kali Linux container with network analysis tools
- **Website**: Nginx web server with a login form
- **DNS Server**: BIND9 recursive DNS resolver for DNS cache poisoning demonstrations

The containers are connected via a Docker bridge network and communicate using fixed IP addresses.

## Components

- **Victim Container** (`172.18.0.10`): Runs an automated script that sends login requests every 5 seconds. Configured to use the local DNS server at 172.18.0.40.
- **Attacker Container** (`172.18.0.20`): Kali Linux with Scapy, tcpdump, nmap, and other security tools
- **Website Container** (`172.18.0.30`): Nginx server that serves a login page and logs authentication attempts
- **DNS Server Container** (`172.18.0.40`): BIND9 recursive DNS resolver that forwards queries to external DNS servers (8.8.8.8, 8.8.4.4). Caches DNS responses for up to 24 hours. Essential for DNS cache poisoning demonstrations as it provides a target DNS server with cacheable responses.

## Setup Instructions

### Prerequisites
- Docker and Docker Compose installed on your system

### Installation Steps

1. **Navigate to the project directory:**
   ```bash
   cd /path/to/Cybersec
   ```

2. **Start the containers:**
   ```bash
   docker-compose up -d
   ```

3. **Verify the setup:**
   ```bash
   docker ps
   ```
   You should see four running containers: victim, attacker, website, and dns.

4. **Check network connectivity:**
   ```bash
   docker exec victim ping -c 2 172.18.0.30
   docker exec attacker ping -c 2 172.18.0.10
   ```

5. **Test DNS server:**
   ```bash
   docker exec victim nslookup example.com 172.18.0.40
   ```
   Should return IP addresses for example.com.

6. **Verify DNS forwarding to 8.8.8.8:**
   
   **Terminal 1** - Monitor DNS traffic:
   ```bash
   docker exec -it dns bash
   tcpdump -i eth0 -n -c 10 'host 8.8.8.8 and port 53'
   ```
   
   **Terminal 2** - Make DNS query:
   ```bash
   docker exec victim nslookup example.com 172.18.0.40
   ```
   
   You should see packets showing DNS server (172.18.0.40) forwarding queries to 8.8.8.8.

7. **If 'victim' refuses to boot up and the error on Docker Desktop states "unable to select packages: curl", run the following command:**
   ```bash
   dos2unix victim_login.sh
   ```

## Basic Usage

### Access the containers:
```bash
# Victim container
docker exec -it victim sh

# Attacker container
docker exec -it attacker sh

# Website container
docker exec -it website sh

# DNS container
docker exec -it dns bash
```

### Monitor activity:
```bash
# View logs from all containers
docker-compose logs -f

# Check login attempts on website
docker exec website tail -f /var/log/nginx/login_attempts.log
```
## Configuration Files

- `docker-compose.yml`: Container definitions and network configuration
- `attacker.Dockerfile`: Kali Linux image with additional security tools
- `dns.Dockerfile`: Debian-based BIND9 DNS server image with tcpdump
- `named.conf.options`: BIND9 DNS server configuration (recursive resolver, forwards to 8.8.8.8)
- `nginx.conf`: Web server configuration
- `victim_login.sh`: Automated login script
- `website/index.html`: Login page
- `website/success.html`: Success page after login

## Stopping the Environment

```bash
docker-compose down
```

## Network Details

- **Network Type**: Docker bridge
- **IP Range**: 172.18.0.0/16
