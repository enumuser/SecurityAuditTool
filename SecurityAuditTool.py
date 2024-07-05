import sys
import socket
import requests
import dns.resolver
import argparse
from html import escape
from bs4 import BeautifulSoup

def subdomain_enum(domain):
    print("[*] Enumerating subdomains...")
    subdomains = []
    wordlist = ['www', 'mail', 'ftp', 'test', 'dev', 'server', 'blog', 'shop', 'webmail', 'remote', 'smtp', 'api', 'ns1', 'ns2', 'support', 'login']
    for sub in wordlist:
        try:
            subdomain = f"{sub}.{domain}"
            dns.resolver.resolve(subdomain, 'A')
            print(f"[+] Found subdomain: {subdomain}")
            subdomains.append(subdomain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
    return subdomains

def port_scan(domain, port_range):
    print("[*] Scanning ports...")
    open_ports = []
    start, end = map(int, port_range.split('-'))
    ports = list(range(start, end + 1))

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            print(f"[-] Error scanning port {port}: {e}")
    return open_ports

def gather_technical_info(domain):
    print("[*] Gathering technical information...")
    tech_info = {}
    for protocol in ["http", "https"]:
        try:
            response = requests.get(f"{protocol}://{domain}", timeout=5)
            headers = response.headers
            server = headers.get('Server', 'Unknown')
            tech_info['Server'] = server
            tech_info['Headers'] = headers
            print(f"[+] Server: {server}")

            soup = BeautifulSoup(response.content, 'html.parser')
            tech_info['Title'] = soup.title.string if soup.title else 'Title not found'
            tech_info['Content'] = response.text
            break
        except requests.RequestException as e:
            print(f"[-] Error gathering technical information with {protocol}: {e}")
            continue
    return tech_info

def detect_technologies(html_content):
    print("[*] Detecting technologies...")
    technologies = {}
    if 'cloudflare' in html_content:
        technologies['Cloudflare'] = 'Web Application Firewall'
    if 'wp-content' in html_content or 'wordpress' in html_content:
        technologies['WordPress'] = 'Content Management System'
    if 'nginx' in html_content:
        technologies['Nginx'] = 'Web Server'
    if 'apache' in html_content:
        technologies['Apache'] = 'Web Server'
    return technologies

def check_vulnerabilities(technical_info, open_ports):
    vulnerabilities = []
    recommendations = []

    server = technical_info.get('Server', '')
    if 'Apache' in server:
        version = server.split('/')[1] if '/' in server else 'Unknown'
        if version != 'Unknown' and version < '2.4.51':
            vulnerabilities.append(f"Outdated Apache server version: {version}")
            recommendations.append("Update Apache server to the latest version.")
    elif 'nginx' in server:
        version = server.split('/')[1] if '/' in server else 'Unknown'
        if version != 'Unknown' and version < '1.21.4':
            vulnerabilities.append(f"Outdated Nginx server version: {version}")
            recommendations.append("Update Nginx server to the latest version.")

    common_vulnerable_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP'}
    for port in open_ports:
        if port in common_vulnerable_ports:
            vulnerabilities.append(f"Open port {port} ({common_vulnerable_ports[port]})")
            recommendations.append(f"Close port {port} if not in use or use secure alternatives.")

    if not vulnerabilities:
        vulnerabilities.append("No vulnerable services found.")
        recommendations.append("None")

    return vulnerabilities, recommendations

def generate_html_report(domain, subdomains, open_ports, technical_info, technologies, vulnerabilities, recommendations):
    print("[*] Generating HTML report...")
    html_content = f"""
    <html>
    <head>
        <title>Security Audit Report for {escape(domain)}</title>
    </head>
    <body>
        <h1>Security Audit Report for {escape(domain)}</h1>

        <h2>Subdomains</h2>
        <ul>
            {''.join(f'<li>{escape(sub)}</li>' for sub in subdomains)}
        </ul>

        <h2>Open Ports</h2>
        <ul>
            {''.join(f'<li>{port}</li>' for port in open_ports)}
        </ul>

        <h2>Technical Information</h2>
        <ul>
            <li>Server: {escape(technical_info.get('Server', 'Unknown'))}</li>
            <li>Title: {escape(technical_info.get('Title', 'Title not found'))}</li>
        </ul>

        <h3>Headers</h3>
        <ul>
            {''.join(f'<li>{escape(header)}: {escape(value)}</li>' for header, value in technical_info.get('Headers', {}).items())}
        </ul>

        <h2>Detected Technologies</h2>
        <ul>
            {''.join(f'<li>{escape(tech)}: {escape(info)}</li>' for tech, info in technologies.items())}
        </ul>

        <h2>Vulnerabilities</h2>
        <ul>
            {''.join(f'<li>{escape(vuln)}</li>' for vuln in vulnerabilities)}
        </ul>

        <h2>Recommendations</h2>
        <ul>
            {''.join(f'<li>{escape(rec)}</li>' for rec in recommendations)}
        </ul>
    </body>
    </html>
    """
    with open('report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    print("[*] Report saved as report.html")

def main():
    parser = argparse.ArgumentParser(description="Security Audit Tool")
    parser.add_argument('domain', help="The domain to scan")
    parser.add_argument('--port-range', default='1-100', help="The range of ports to scan (default: 1-100)")

    args = parser.parse_args()
    domain = args.domain
    port_range = args.port_range

    subdomains = subdomain_enum(domain)
    open_ports = port_scan(domain, port_range)
    technical_info = gather_technical_info(domain)

    if 'Content' in technical_info:
        technologies = detect_technologies(technical_info['Content'])
    else:
        technologies = {}

    vulnerabilities, recommendations = check_vulnerabilities(technical_info, open_ports)

    generate_html_report(domain, subdomains, open_ports, technical_info, technologies, vulnerabilities, recommendations)
    print("[*] Information gathering and security audit completed.")

if __name__ == "__main__":
    main()
