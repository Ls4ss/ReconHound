<h1 align="center">ReconHound - Attack Surface Management</h1>

<div align="center">

<img width="90" src="https://avatars.githubusercontent.com/u/129181562?s=200&v=4" alt="ReconHound Logo">

### Modern External Attack Surface Mapping & Threat Intelligence Platform
**Asynchronous • Modular • High-Concurrency • EPSS + CISA KEV Prioritization • Masscan & Nuclei Active Scanning • Shodan • Censys • crt.sh • OTX**

[![Website: detecti.com.br](https://img.shields.io/badge/Official_Website-detecti.com.br-00d4ff.svg)](https://detecti.com.br)
[![Documentation: Official Docs](https://img.shields.io/badge/Documentation-Official_Docs-8A2BE2.svg)](https://detecti.com.br/docs/reconhound/en.html)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 📚 Official Documentation

> **For complete guides, installation, CLI usage, architecture, and threat intelligence scoring, please visit the [ReconHound Official Documentation](https://detecti.com.br/docs/reconhound/en.html).**

**ReconHound** is a high-performance External Attack Surface Management (EASM) and Threat Intelligence ecosystem. It maps exposed internet infrastructure, performs targeted vulnerability validation, and enriches findings with real-world exploitation risk data (FIRST EPSS + CISA KEV + Threat Actor Attribution).

The platform consists of two main components:
1. **ReconExec (`reconx`)**: The high-speed, asynchronous command-line execution engine.
2. **ReconHound Dashboard**: The interactive, Cytoscape-powered graphical UI for attack surface visualization.

---

## 📦 Quick Installation

```bash
# 1. Download and install from PyPI
pip install reconexec

# 2. Run the automated setup routine
reconx config-check --setup

# 3. Explore commands
reconx --help
```

*For prerequisites like Masscan and Nuclei, and advanced API keys configuration, check the [Installation Guide](https://detecti.com.br/docs/reconhound/en.html#setup-install).*

---

## 💻 ReconExec (CLI) Usage Examples

```bash
# Recon a single IP or CIDR Subnet
reconx recon 142.250.191.68
reconx recon 142.250.191.0/24

# Recon a Domain (Subdomains + Reverse WHOIS + Infrastructure)
reconx recon spacex.com

# Recon a Batch Target List from File
reconx recon targets.txt

# Fetch Threat Intelligence for a specific CVE
reconx intel CVE-2021-44228

# Start the Interactive EASM Web Dashboard (ReconHound)
reconx hound start
```

*For advanced queries, vulnerability filtering, and reporting, see the [CLI Usage Guide](https://detecti.com.br/docs/reconhound/en.html#cli-quickstart).*

---

## 🏗️ Architecture

```
ReconHound/
├── pyproject.toml           # Modern Packaging & Dependency Definition
├── README.md                # Project Overview
├── reconexec/               # Main CLI Engine Package (reconx)
│   ├── cli.py               # Typer & Rich Command Line Interface entrypoint
│   ├── config.py            # Pydantic Settings, .env & Environment Loader
│   ├── core/                    
│   │   ├── engine.py        # Asynchronous Multi-Stage Pipeline & Correlation Engine
│   │   ├── models.py        # Unified Pydantic v2 Finding, Host & Intel Data Models
│   │   └── database/        
│   │       ├── schema.py    # SQLite Relational Schema
│   │       └── storage.py   # DatabaseManager Persistence & Query Layer
│   ├── data/                # Central Scan Data Directory
│   │   └── dbs/             # Persistent SQLite Attack Surface Databases (.sqlite)
│   ├── modules/             # Plug-and-Play Intelligence Collectors
│   │   ├── crtsh.py         # Certificate Transparency Subdomain Enumeration
│   │   ├── securitytrails.py# SecurityTrails Historical OSINT
│   │   ├── reverse_whois.py # Reverse WHOIS (Hybrid WhoisFreaks + Free Fallback)
│   │   ├── shodan.py        # Shodan Host, DNS, Range & Query Scanner
│   │   ├── censys.py        # Censys Platform API v3 Asset & Host Intelligence
│   │   ├── alienvault.py    # OTX Threat Attribution & Passive DNS
│   │   ├── masscan.py       # High-Speed Active Port Scanner
│   │   ├── nuclei.py        # Asynchronous Nuclei Vulnerability Scanner Engine
│   │   ├── nvd.py           # NVD 2.0 (CVSS/CWE) + EPSS Probability + CISA KEV
│   │   └── exploitdb.py     # ExploitDB (searchsploit) & GitHub PoC Collector
│   ├── reporters/           # Report Generation Subsystem (CSV, HTML, JSON, Markdown)
│   ├── web/                 # Interactive EASM Dashboard Subsystem (ReconHound)
│   │   ├── api/             
│   │   │   ├── auth.py      # JWT Authentication & Authorization
│   │   │   ├── graph_builder.py # Cytoscape Graph Topology Builder
│   │   │   └── routes.py    # FastAPI Endpoints
│   │   ├── static/          # WebGUI Assets (CSS, JS, index.html)
│   │   ├── process_manager.py # Background Daemon Server Manager
│   │   └── server.py        # Asynchronous FastAPI & Uvicorn Server
│   └── utils/               # HTTP client, Logger, Setup, and Updater utilities
└── tests/                   # Pytest Unit & Integration Test Suite
```

---

## 🛠️ Creator and Maintainer

<a href="https://github.com/Ls4ss">
  <img src="https://avatars.githubusercontent.com/u/25537761?v=4" width="100px;" style="border-radius: 50%;" alt="Ls4ss Profile"/>
  <br />
  <sub><b>Lucas S. (Ls4ss)</b></sub>
</a>
<br />
<sub>Developed by <b><a href="https://detecti.com.br" target="_blank">DetecTI Security</a></b></sub>

Feel free to open Issues or submit Pull Requests to contribute!
