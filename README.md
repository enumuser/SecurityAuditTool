# Security Audit Tool

A security audit tool for enumerating subdomains, scanning open ports, gathering technical information, detecting technologies, and checking for vulnerabilities.

## Features

- Enumerates subdomains using a predefined wordlist.
- Scans a range of ports to identify open ports.
- Gathers technical information about the target domain.
- Detects technologies used on the target website.
- Checks for common vulnerabilities and provides recommendations.
- Generates an HTML report with all gathered information.

## Requirements

- Python 3
- Libraries: `requests`, `dnspython`, `beautifulsoup4`

You can install the required libraries using `pip`:

```bash
pip install requests dnspython beautifulsoup4
Usage
Command Line Arguments
domain: The target domain to scan.
--port-range: The range of ports to scan (default: 1-100).

## Usage

python security_audit_tool.py example.com --port-range 1-1000
