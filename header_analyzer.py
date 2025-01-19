import requests
import argparse
from colorama import Fore, Style
import json
from urllib.parse import urlparse
import socket
import ssl

def analyze_headers(url):
    try:
        # Add scheme if not present
        if not urlparse(url).scheme:
            url = "http://" + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Make the request
        response = requests.get(url, allow_redirects=True)
        
        print(f"\n{Fore.CYAN}[+] Analyzing headers for: {url}{Style.RESET_ALL}")
        
        # Analyze security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header - TLS connection not enforced',
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME-type sniffing protection', 
            'X-XSS-Protection': 'Missing XSS protection',
            'Content-Security-Policy': 'Missing CSP header',
            'Referrer-Policy': 'Missing referrer policy',
            'Permissions-Policy': 'Missing permissions policy header',
            'Cross-Origin-Embedder-Policy': 'Missing COEP header',
            'Cross-Origin-Opener-Policy': 'Missing COOP header',
            'Cross-Origin-Resource-Policy': 'Missing CORP header'
        }

        print(f"\n{Fore.GREEN}[+] Response Headers:{Style.RESET_ALL}")
        for header, value in response.headers.items():
            print(f"{Fore.YELLOW}{header}{Style.RESET_ALL}: {value}")
            if header in security_headers:
                del security_headers[header]

        print(f"\n{Fore.RED}[!] Missing Security Headers:{Style.RESET_ALL}")
        for header, description in security_headers.items():
            print(f"{Fore.RED}[-] {header}: {description}{Style.RESET_ALL}")

        # Server info
        server = response.headers.get('Server', 'Not disclosed')
        print(f"\n{Fore.BLUE}[+] Server Information:{Style.RESET_ALL}")
        print(f"Server: {server}")
        print(f"Status Code: {response.status_code}")

        # Check for information disclosure
        sensitive_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'Server']
        print(f"\n{Fore.YELLOW}[+] Potential Information Disclosure:{Style.RESET_ALL}")
        for header in sensitive_headers:
            if header in response.headers:
                print(f"{Fore.RED}[-] {header}: {response.headers[header]} (Technology disclosure){Style.RESET_ALL}")

        # Check SSL/TLS (if HTTPS)
        if parsed_url.scheme == 'https':
            print(f"\n{Fore.BLUE}[+] SSL/TLS Information:{Style.RESET_ALL}")
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        print(f"SSL Version: {ssock.version()}")
                        print(f"Certificate Expires: {cert['notAfter']}")
            except Exception as e:
                print(f"{Fore.RED}[-] SSL/TLS Error: {e}{Style.RESET_ALL}")

        # Save headers to file
        with open('headers.json', 'w') as f:
            json.dump(dict(response.headers), f, indent=4)
        print(f"\n{Fore.GREEN}[+] Headers saved to headers.json{Style.RESET_ALL}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Header Analyzer")
    parser.add_argument("url", help="Target URL to analyze")
    args = parser.parse_args()

    analyze_headers(args.url)

# Example usage: python header_analyzer.py example.com
