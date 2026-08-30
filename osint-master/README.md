# 🔍 OSINT Master

A multi-function **Open Source Intelligence (OSINT)** command-line tool written in **Go**.

OSINT Master performs **passive reconnaissance** using publicly available information. It retrieves information about IP addresses, usernames, domains, and (bonus) full names while respecting ethical and legal OSINT practices.

> **Educational Project**
>
> This project was developed for educational purposes to demonstrate OSINT techniques, API integration, DNS analysis, SSL inspection, and defensive cybersecurity practices.

---

# 📚 Table of Contents

* Overview
* Features
* Development Environment
* Requirements
* Installation
* Project Structure
* Usage
* Command Line Options
* Output
* APIs & Data Sources
* Implementation Details
* Error Handling
* API Rate Limits
* Security Considerations
* Ethical & Legal Guidelines
* Troubleshooting
* Known Limitations
* Future Improvements
* License

---

# 📖 Overview

Open Source Intelligence (OSINT) is the process of collecting information from publicly available sources.

OSINT Master automates several passive reconnaissance techniques, allowing security professionals and students to gather information about:

* IP addresses
* Usernames
* Domains
* Subdomains
* SSL certificates
* DNS records
* Potential subdomain takeover risks

The application only gathers publicly accessible information and performs **no intrusive or offensive actions**.

---

# ✨ Features

## Mandatory Features

### 🌍 IP Address Lookup

Retrieve:

* Country
* Region
* City
* ISP
* ASN
* Coordinates (when available)
* Abuse information
* Historical threat information (when available)

---

### 👤 Username Search

Search a username across multiple public platforms.

Supported platforms include:

* GitHub
* GitLab
* Reddit
* X (Twitter)
* Facebook
* Instagram
* LinkedIn
* Medium

Retrieve public information when available:

* Profile existence
* Bio
* Followers
* Public activity

---

### 🌐 Domain Enumeration

* DNS resolution
* Subdomain discovery
* Resolve subdomain IP addresses
* SSL certificate inspection
* CNAME inspection
* Detection of possible subdomain takeover risks

---

### 💾 Output Management

Results are displayed in the terminal and can also be saved to a text file using the `-o` option.

---

## ⭐ Bonus Features

* Full Name Search (`-n`)
* Username variation generation
* OSINT search links
* Additional defensive analysis

---

# 🖥 Development Environment

For security and isolation, this project was developed and tested inside a Linux environment.

Recommended environment:

* Ubuntu 22.04 LTS
* VirtualBox or VMware
* 2 GB RAM
* NAT networking

## Why use a Virtual Machine?

Using a virtual machine provides:

* Isolation from the host operating system
* Protection of API keys and credentials
* Safe testing environment
* Easy rollback using snapshots
* Reduced risk when interacting with unknown domains or IP addresses

Although this tool performs only passive OSINT, developing inside a VM follows cybersecurity best practices.

---

# ⚙ Requirements

* Go 1.20 or later
* Internet connection
* Linux, macOS or Windows

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/<your-username>/osint-master.git
cd osint-master
```

Install dependencies

```bash
go mod tidy
```

Build

```bash
go build -o osintmaster
```

Run

```bash
./osintmaster --help
```

---

# 📁 Project Structure

```
osint-master/
│
├── cmd/
├── internal/
│   ├── api/
│   ├── domain/
│   ├── ip/
│   ├── username/
│   ├── fullname/
│   ├── output/
│   └── utils/
│
├── output/
│
├── README.md
├── go.mod
├── go.sum
└── .gitignore
```

> Adjust this tree if your project structure is different.

---

# 💻 Usage

Display help

```bash
./osintmaster --help
```

---

## IP Lookup

```bash
./osintmaster -i 8.8.8.8
```

Save output

```bash
./osintmaster -i 8.8.8.8 -o result.txt
```

Example

```
IP Address : 8.8.8.8

Country : United States
Region  : California
City    : Mountain View
ISP     : Google LLC
ASN     : AS15169

Abuse Reports : None
```

---

## Username Search

```bash
./osintmaster -u torvalds
```

Save output

```bash
./osintmaster -u torvalds -o user.txt
```

Example

```
GitHub      : Found
Instagram   : Not Found
LinkedIn    : Found
Twitter     : Found

Followers : 250000
Bio       : Linux creator
Activity  : Active
```

---

## Domain Enumeration

```bash
./osintmaster -d github.com
```

Save output

```bash
./osintmaster -d github.com -o domain.txt
```

Example

```
Main Domain

github.com

Subdomains

api.github.com
docs.github.com
www.github.com

SSL Certificate

Valid

Potential Takeover Risk

None detected
```

---

## Bonus Full Name Search

```bash
./osintmaster -n "John Smith"
```

---

# 📝 Command Line Options

| Option   | Description              |
| -------- | ------------------------ |
| `-i`     | IP Address lookup        |
| `-u`     | Username lookup          |
| `-d`     | Domain enumeration       |
| `-n`     | Full Name search (Bonus) |
| `-o`     | Save results to a file   |
| `--help` | Display help             |

---

# 📂 Output

Results are displayed in the terminal.

When using

```bash
-o filename.txt
```

the application saves the same information inside the specified file.

Example

```
output/

result.txt
user.txt
domain.txt
```

---

# 🌐 APIs & Data Sources

This application uses public APIs and Internet resources.

Examples include:

### IP Geolocation API

Used to retrieve:

* Country
* City
* Region
* Coordinates
* ISP
* ASN

---

### Abuse Database

Used to retrieve:

* Public abuse reports
* Reputation information

---

### DNS Resolver

Used to:

* Resolve domains
* Resolve subdomains
* Retrieve DNS records

---

### SSL Inspection

Used to retrieve:

* Certificate issuer
* Expiration date
* Validation status

---

### Public Social Platforms

Used to verify usernames and retrieve publicly available profile information.

---

# 🛠 Implementation Details

The application was fully implemented in Go.

It **does not execute or wrap existing OSINT command-line tools** such as:

* Sherlock
* Subfinder
* theHarvester
* Amass

Instead, the project implements its own logic by:

* Performing HTTP requests to public APIs
* Parsing JSON responses
* Resolving DNS records
* Inspecting SSL certificates
* Performing HTTP response analysis
* Detecting possible subdomain takeover risks using DNS and CNAME analysis

The project uses external APIs only as data sources.

---

# ⚠ Error Handling

The application validates all user input before processing.

Handled scenarios include:

* Invalid IP addresses
* Invalid domains
* Empty usernames
* Network failures
* API timeouts
* HTTP errors
* DNS failures
* SSL errors
* API rate limiting

Meaningful error messages are displayed instead of unexpected crashes.

---

# ⏱ API Rate Limits

Some external services enforce request limits.

If a limit is reached, the application:

* Detects the error
* Displays an informative message
* Exits gracefully

No unexpected panic occurs.

---

# 🔒 Security Considerations

OSINT Master performs **passive reconnaissance only**.

The application never:

* exploits vulnerabilities
* performs brute-force attacks
* scans private networks
* bypasses authentication
* performs unauthorized access

It only retrieves publicly available information.

Sensitive API keys should never be committed to version control.

When possible, use environment variables for secret values.

Running the project inside a virtual machine is recommended for additional isolation.

---

# ⚖ Ethical & Legal Guidelines

This project is intended **for educational purposes only**.

Always:

* Obtain permission before investigating systems.
* Respect user privacy.
* Collect only publicly available information.
* Follow local laws and regulations.
* Respect API Terms of Service.
* Report discovered vulnerabilities responsibly.

Misusing this software against systems without authorization may be illegal.

The author assumes no responsibility for misuse.

---

# 🔧 Troubleshooting

## Build fails

Run

```bash
go mod tidy
```

and rebuild.

---

## Permission denied

```bash
chmod +x osintmaster
```

---

## No Internet connection

Verify your network connection.

---

## API unavailable

Wait a few minutes and retry.

---

## Empty results

Some services may temporarily restrict access or the requested information may not be publicly available.

---

# ⚠ Known Limitations

* IP geolocation is approximate and depends on the provider.
* Some APIs enforce rate limits.
* Social media platforms may restrict publicly available information.
* DNS propagation may affect subdomain enumeration.
* Some SSL information depends on server configuration.
* Results depend on third-party service availability.

---

# 🚀 Future Improvements

Possible future enhancements include:

* PDF report generation
* HTML reports
* JSON export
* Graphical User Interface (GUI)
* Additional OSINT providers
* API response caching
* Parallel request optimization

---

# 📜 License

This project was developed for educational purposes as part of an OSINT learning project.

It demonstrates passive reconnaissance techniques while promoting ethical and responsible cybersecurity practices.


add this bonus at the end 
        ==> PDF Generation: Add a feature to generate your OSINT results as PDF files.