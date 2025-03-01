#!/bin/bash

# Web Reconnaissance Tool Runner Script

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "nmap is not installed. Installing nmap..."
    apt-get update && apt-get install -y nmap
fi

# Check if dependencies are installed
if ! pip3 list | grep -q dnspython; then
    echo "Installing required Python packages..."
    pip3 install -r requirements.txt
fi

# Run the tool with the provided arguments
python3 web_recon.py "$@"
