# XSNIFFER is an Advanced Network Sniffer

![pro](https://github.com/user-attachments/assets/b37aa225-6a86-489e-bc80-7206a5584f49)


## Description
XSNIFFER is an advanced Python-based network sniffer that captures and analyzes network traffic in real-time. It provides detailed insights into HTTP requests, DNS queries, API calls, and other network protocols. The tool includes a built-in REST API for monitoring statistics and supports packet capture (PCAP) logging.

## Features
- **Real-time Packet Analysis**: Captures TCP, UDP, HTTP, DNS, and API traffic
- **Encrypted State Management**: Securely stores data using Fernet encryption
- **REST API**: Access real-time stats via `http://localhost:8080/stats`
- **PCAP Logging**: Optionally saves packets to `capture.pcap`
- **Multithreaded Processing**: Efficient packet handling with worker threads
- **Custom Filters**: Supports BPF syntax (e.g., `port 80`, `host 8.8.8.8`)

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/calebpentest/XSNIFFER
cd XSNIFFER
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```
*Requires Python 3.6+*

### 3. Run XSNIFFER
```bash
sudo python3 xsniffer.py [OPTIONS]
```

## Usage Examples
| Command | Description |
|---------|-------------|
| `sudo python3 xsniffer.py` | Default capture (all traffic) |
| `sudo python3 xsniffer.py -f "port 443"` | HTTPS traffic only |
| `sudo python3 xsniffer.py --pcap` | Save to `capture.pcap` |

### Command-line Arguments
| Argument | Description | Example |
|----------|-------------|---------|
| `-f`, `--filter` | BPF filter | `"host 8.8.8.8"` |
| `-p`, `--pcap` | Enable PCAP logging | N/A |

## API Access
```bash
curl http://localhost:8080/stats
```
*Returns JSON packet statistics*

## Sample Output
```
[HTTP] 192.168.1.100 -> example.com/login
[DNS] Query: google.com  
[API] 10.0.0.2 -> 10.0.0.3
```

## Configuration
Edit `Config` class to modify:
- `api_port`: Change API listening port (default: 8080)
- `filter`: Set default BPF filter

## Security Notes
🔐 **Requires root privileges** for packet capture  
🔑 Encryption keys are auto-generated (not persisted)  
⚠️ **Use responsibly**: Only monitor networks you own and have been given permission to access

## License
Free for non-commercial use. Author retains all rights.
---

**Author**: C4l3bpy  
**Report Issues**: calebepentest@gmail.com
```
