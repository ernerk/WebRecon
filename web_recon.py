#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import subprocess
import sys
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import nmap
import time
import os

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WebRecon:
    def __init__(self, target_url, output_file=None, threads=10, ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"):
        self.target_url = self._clean_url(target_url)
        self.base_domain = self._extract_base_domain(self.target_url)
        self.output_file = output_file
        self.threads = threads
        self.ports = ports
        self.subdomains = set()
        self.open_ports = {}
        
    def _clean_url(self, url):
        """Remove protocol and path from URL to get the domain"""
        url = url.lower()
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        return url.split('/', 1)[0]
    
    def _extract_base_domain(self, domain):
        """Extract the base domain from a subdomain"""
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain
    
    def print_banner(self):
        """Print a cool banner for the tool"""
        banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════╗
║                                                      ║
║  {Colors.GREEN}██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗{Colors.BLUE}  ║
║  {Colors.GREEN}██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗{Colors.BLUE} ║
║  {Colors.GREEN}██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║   ██║{Colors.BLUE} ║
║  {Colors.GREEN}██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║   ██║{Colors.BLUE} ║
║  {Colors.GREEN}╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╔╝{Colors.BLUE} ║
║   {Colors.GREEN}╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ {Colors.BLUE} ║
║                                                      ║
╚══════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.BOLD}[*] Web Reconnaissance Tool{Colors.ENDC}
{Colors.BOLD}[*] Target: {Colors.GREEN}{self.target_url}{Colors.ENDC}
"""
        print(banner)
    
    def check_dependencies(self):
        """Check if all required tools are installed"""
        print(f"{Colors.BOLD}[*] Checking dependencies...{Colors.ENDC}")
        
        try:
            import dns.resolver
            print(f"{Colors.GREEN}[+] dnspython is installed{Colors.ENDC}")
        except ImportError:
            print(f"{Colors.FAIL}[-] dnspython is not installed. Install with: pip install dnspython{Colors.ENDC}")
            sys.exit(1)
            
        try:
            import requests
            print(f"{Colors.GREEN}[+] requests is installed{Colors.ENDC}")
        except ImportError:
            print(f"{Colors.FAIL}[-] requests is not installed. Install with: pip install requests{Colors.ENDC}")
            sys.exit(1)
            
        try:
            import nmap
            print(f"{Colors.GREEN}[+] python-nmap is installed{Colors.ENDC}")
        except ImportError:
            print(f"{Colors.FAIL}[-] python-nmap is not installed. Install with: pip install python-nmap{Colors.ENDC}")
            sys.exit(1)
            
        try:
            import tqdm
            print(f"{Colors.GREEN}[+] tqdm is installed{Colors.ENDC}")
        except ImportError:
            print(f"{Colors.FAIL}[-] tqdm is not installed. Install with: pip install tqdm{Colors.ENDC}")
            sys.exit(1)
            
        # Check if nmap is installed on the system
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            print(f"{Colors.GREEN}[+] nmap is installed{Colors.ENDC}")
        except (subprocess.SubprocessError, FileNotFoundError):
            print(f"{Colors.FAIL}[-] nmap is not installed. Install with: apt-get install nmap{Colors.ENDC}")
            sys.exit(1)
        
        print(f"{Colors.GREEN}[+] All dependencies are installed{Colors.ENDC}")
    
    def find_subdomains(self):
        """Find subdomains using various techniques"""
        print(f"\n{Colors.BOLD}[*] Finding subdomains for {self.base_domain}...{Colors.ENDC}")
        
        # Common subdomain list
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
            "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
            "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
            "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
            "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
            "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
            "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps", "download",
            "remote", "db", "forums", "store", "relay", "files", "newsletter", "app", "live",
            "owa", "en", "start", "sms", "office", "exchange", "ipv4", "mail3", "help", "blogs",
            "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor", "login", "service",
            "correo", "www4", "moodle", "it", "gateway", "gw", "i", "stat", "stage", "ldap",
            "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2", "online", "ad", "survey",
            "data", "radio", "extranet", "test2", "mssql", "dns3", "jobs", "services", "panel",
            "irc", "hosting", "cloud", "de", "gmail", "s", "bbs", "cs", "ww", "mrtg", "git",
            "image", "members", "poczta", "s1", "meet", "preview", "fr", "cloudflare", "dev2",
            "photo", "jabber", "legacy", "go", "es", "ssh", "redmine", "partner", "vps", "server1",
            "sv", "ns6", "webmail2", "av", "community", "cacti", "time", "sftp", "lib", "facebook",
            "www5", "smtp1", "feeds", "w", "games", "ts", "alumni", "dl", "s2", "phpmyadmin",
            "archive", "cn", "tools", "stream", "projects", "elearning", "im", "iphone", "control",
            "voip", "test1", "ws", "rss", "sp", "wwww", "vpn2", "jira", "list", "connect",
            "gallery", "billing", "mailer", "update", "pda", "game", "ns0", "testing", "sandbox",
            "job", "events", "dialin", "ml", "fb", "videos", "music", "a", "partners", "mailhost",
            "downloads", "reports", "ca", "router", "speedtest", "local", "training", "edu", "bugs",
            "manage", "s3", "status", "host2", "ww2", "marketing", "conference", "content", "network",
            "firewall", "repository", "ftp1", "design", "mirror", "sms2", "plus", "customers",
            "smtp3", "devel", "password", "us", "mambo", "url", "vpn1", "master", "mail4", "www6",
            "site", "tracker", "webdav", "docs2", "ts2", "ns7", "ns8", "collab", "gateway2", "proxy2",
            "ps", "sip2", "smtp4", "www7", "corp", "internal", "mailgate", "pay", "access", "jenkins",
            "docker", "gitlab", "sonar", "nexus", "grafana", "prometheus", "kubernetes", "rancher"
        ]
        
        found_subdomains = set()
        
        # Try DNS brute force
        print(f"{Colors.BLUE}[+] Performing DNS brute force...{Colors.ENDC}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for subdomain in common_subdomains:
                futures.append(executor.submit(self._check_subdomain, subdomain))
            
            for future in tqdm(futures, total=len(common_subdomains), desc="Progress", unit="subdomain"):
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        # Add the found subdomains to the main set
        self.subdomains.update(found_subdomains)
        
        # Print the results
        if self.subdomains:
            print(f"\n{Colors.GREEN}[+] Found {len(self.subdomains)} subdomains:{Colors.ENDC}")
            for subdomain in sorted(self.subdomains):
                print(f"  {Colors.BLUE}➜{Colors.ENDC} {subdomain}")
        else:
            print(f"\n{Colors.WARNING}[-] No subdomains found{Colors.ENDC}")
        
        return self.subdomains
    
    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        full_domain = f"{subdomain}.{self.base_domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            return None
    
    def scan_ports(self):
        """Scan for open ports on the target and subdomains"""
        targets = list(self.subdomains)
        if not self.target_url in targets:
            targets.append(self.target_url)
        
        if not targets:
            print(f"\n{Colors.WARNING}[-] No targets to scan for open ports{Colors.ENDC}")
            return
        
        print(f"\n{Colors.BOLD}[*] Scanning for open ports on {len(targets)} targets...{Colors.ENDC}")
        print(f"{Colors.BLUE}[+] Port range: {self.ports}{Colors.ENDC}")
        
        nm = nmap.PortScanner()
        
        for target in tqdm(targets, desc="Scanning targets", unit="host"):
            try:
                # Get IP address
                ip = socket.gethostbyname(target)
                
                # Scan the target
                print(f"\n{Colors.BLUE}[+] Scanning {target} ({ip})...{Colors.ENDC}")
                nm.scan(ip, self.ports, arguments='-T4 -sV')
                
                open_ports = []
                
                # Process results
                for proto in nm[ip].all_protocols():
                    lport = sorted(nm[ip][proto].keys())
                    for port in lport:
                        if nm[ip][proto][port]['state'] == 'open':
                            service = nm[ip][proto][port]['name']
                            version = nm[ip][proto][port]['product'] + " " + nm[ip][proto][port]['version']
                            version = version.strip()
                            
                            port_info = {
                                'port': port,
                                'service': service,
                                'version': version
                            }
                            
                            open_ports.append(port_info)
                
                if open_ports:
                    self.open_ports[target] = open_ports
                    print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports on {target}:{Colors.ENDC}")
                    
                    for port_info in open_ports:
                        port = port_info['port']
                        service = port_info['service']
                        version = port_info['version']
                        
                        if version:
                            print(f"  {Colors.BLUE}➜{Colors.ENDC} {port}/tcp - {service} ({version})")
                        else:
                            print(f"  {Colors.BLUE}➜{Colors.ENDC} {port}/tcp - {service}")
                else:
                    print(f"{Colors.WARNING}[-] No open ports found on {target}{Colors.ENDC}")
                    
            except (socket.gaierror, socket.error) as e:
                print(f"{Colors.FAIL}[-] Error scanning {target}: {str(e)}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[-] Error scanning {target}: {str(e)}{Colors.ENDC}")
        
        return self.open_ports
    
    def save_results(self):
        """Save the results to a file"""
        if not self.output_file:
            return
        
        print(f"\n{Colors.BOLD}[*] Saving results to {self.output_file}...{Colors.ENDC}")
        
        with open(self.output_file, 'w') as f:
            f.write(f"Web Reconnaissance Results for {self.target_url}\n")
            f.write(f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            # Save subdomains
            f.write("Subdomains:\n")
            f.write("-" * 60 + "\n")
            if self.subdomains:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
            else:
                f.write("No subdomains found\n")
            
            f.write("\n" + "=" * 60 + "\n\n")
            
            # Save open ports
            f.write("Open Ports:\n")
            f.write("-" * 60 + "\n")
            if self.open_ports:
                for target, ports in self.open_ports.items():
                    f.write(f"\nTarget: {target}\n")
                    f.write("-" * 40 + "\n")
                    
                    if ports:
                        for port_info in ports:
                            port = port_info['port']
                            service = port_info['service']
                            version = port_info['version']
                            
                            if version:
                                f.write(f"{port}/tcp - {service} ({version})\n")
                            else:
                                f.write(f"{port}/tcp - {service}\n")
                    else:
                        f.write("No open ports found\n")
            else:
                f.write("No open ports found on any target\n")
        
        print(f"{Colors.GREEN}[+] Results saved to {self.output_file}{Colors.ENDC}")
    
    def run(self):
        """Run the full reconnaissance"""
        self.print_banner()
        self.check_dependencies()
        self.find_subdomains()
        self.scan_ports()
        self.save_results()
        
        print(f"\n{Colors.BOLD}[*] Reconnaissance completed for {self.target_url}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description='Web Reconnaissance Tool')
    parser.add_argument('-t', '--target', required=True, help='Target URL or domain')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-p', '--ports', default="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080", 
                        help='Ports to scan (comma-separated)')
    parser.add_argument('-j', '--threads', type=int, default=10, help='Number of threads for scanning')
    
    args = parser.parse_args()
    
    try:
        recon = WebRecon(args.target, args.output, args.threads, args.ports)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
