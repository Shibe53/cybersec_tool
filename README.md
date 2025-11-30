# 2IC80 Tool for Attacks

A custom tool that offers a selection of customizable attacks to use. This can be found in the folder 'tool'.

## How to run the ARP Poisoning (WIP)

1. Put the file 'arp_poisoning.py' on the attacker machine.

2. Run it using `python3 arp.py` (make sure scapy is installed).

3. Input the interface (e.g., eth0), victim IP, and the website/router's IP.

## CyberSec Network Testing Environment

A Docker-based setup for cybersecurity testing with three interconnected containers. This can be found in the folder 'network'.

## System Description

This environment creates a private network with three containers:
- **Victim**: Alpine Linux container that sends HTTP requests
- **Attacker**: Kali Linux container with network analysis tools
- **Website**: Nginx web server with a login form

The containers are connected via a Docker bridge network and communicate using fixed IP addresses.

## Components

- **Victim Container** (`172.18.0.10`): Runs an automated script that sends login requests every 5 seconds
- **Attacker Container** (`172.18.0.20`): Kali Linux with Scapy, tcpdump, nmap, and other security tools
- **Website Container** (`172.18.0.30`): Nginx server that serves a login page and logs authentication attempts

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
   You should see three running containers: victim, attacker, and website.

4. **Check network connectivity:**
   ```bash
   docker exec victim ping -c 2 172.18.0.30
   docker exec attacker ping -c 2 172.18.0.10
   ```
5. **If 'victim' refuses to boot up and the error on Docker Desktop states "unable to select packages: curl", run the following command:**
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
