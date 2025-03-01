# Web Reconnaissance Tool

A terminal-based web reconnaissance tool. This tool scans subdomains of a given website and detects open ports.

## Features

- Subdomain discovery
- Port scanning
- Service and version detection
- Multithreading support
- Save results to file

## Requirements

- Python 3.6+
- nmap
- The following Python packages:
  - dnspython
  - requests
  - python-nmap
  - tqdm

## Installation

1. Install the requirements:

```bash
pip install -r requirements.txt
```

2. If nmap is not installed on Kali Linux:

```bash
apt-get install nmap
```

## Installation on Kali Linux

Follow these steps to install the tool on Kali Linux:

1. First, download the project to your computer:

```bash
git clone https://github.com/ernerk/WebRecon.git
cd WebRecon
```

2. Install the required packages:

```bash
pip3 install -r requirements.txt
```

3. Make sure nmap is installed:

```bash
sudo apt-get update && sudo apt-get install -y nmap
```

4. Set execution permissions:

```bash
chmod +x run.sh
```

5. Run the tool:

```bash
./run.sh -t example.com
```

Alternatively, you can run the tool directly with Python:

```bash
python3 web_recon.py -t example.com
```

## Usage

```bash
python web_recon.py -t example.com
```

### Parameters

- `-t, --target`: Target URL or domain name (required)
- `-o, --output`: Filename to save results (optional)
- `-p, --ports`: Ports to scan (comma-separated, default: 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080)
- `-j, --threads`: Number of threads for scanning (default: 10)

### Examples

Simple scan:
```bash
python web_recon.py -t example.com
```

Save results to file:
```bash
python web_recon.py -t example.com -o results.txt
```

Scan specific ports:
```bash
python web_recon.py -t example.com -p 80,443,8080
```

Increase number of threads:
```bash
python web_recon.py -t example.com -j 20
```

## Security Note

Only use this tool on systems you have permission to scan. Unauthorized scanning may cause legal issues.
