# Zeusv5 - Automated Reconnaissance Tool

Zeusv5 is a powerful and modular bash script designed to automate the reconnaissance phase of penetration testing. It integrates a wide range of tools to perform tasks such as subdomain enumeration, parameter collection, JavaScript analysis, CMS detection, vulnerability scanning, and more. The script features a text-based GUI using `dialog` for an interactive user experience.

---

## Features

- **Subdomain Enumeration**: Uses `amass` and `subdominator` for comprehensive subdomain discovery.
- **Parameter Collection**: Collects parameters from live subdomains using `waybackurls` and `gau`.
- **JavaScript Analysis**: Extracts and analyzes JavaScript files for secrets using `SecretFinder`.
- **CMS Detection**: Detects CMS platforms (e.g., WordPress) using `whatweb` and performs CMS-specific scans.
- **Vulnerability Scanning**: Runs `nuclei` for various vulnerabilities and `sqlmap` for SQL injection testing.
- **Web Crawling**: Uses `gospider` for crawling and discovering additional URLs.
- **Endpoint Fuzzing**: Performs directory fuzzing using `ffuf`.
- **DNS Enumeration**: Uses `dnsrecon` for DNS information gathering.
- **Protocol Analysis**: Runs `nmap` for port scanning and protocol analysis.
- **Metadata Extraction**: Extracts metadata from files using `exiftool`.
- **Reporting**: Generates HTML and PDF reports summarizing findings.
- **Text-Based GUI**: Provides an interactive menu using `dialog`.

