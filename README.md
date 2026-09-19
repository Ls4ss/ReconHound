<h1 align="center">DetecTI - Attack Surface Management</h1>

<div align="center">

<img width="90" src="https://avatars.githubusercontent.com/u/129181562?s=200&v=4" alt="DetecTI Security Logo">

### Modern External Attack Surface Mapping & Threat Intelligence Engine
**Asynchronous • Modular • High-Concurrency • EPSS + CISA KEV Prioritization • Masscan & Nuclei Active Scanning • Shodan • Censys • crt.sh • Reverse WHOIS**

[![Website: detecti.com.br](https://img.shields.io/badge/Official_Website-detecti.com.br-00d4ff.svg)](https://detecti.com.br)
[![Documentation: Official Docs](https://img.shields.io/badge/Documentation-Official_Docs-8A2BE2.svg)](https://detecti.com.br/docs/detecti-cli/en.html)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 📚 Official Documentation

> **For complete guides, installation, CLI usage, architecture, and threat intelligence scoring, please visit the [DetecTI-CLI Official Documentation](https://detecti.com.br/docs/detecti-cli/en.html).**

**DetecTI-CLI** is a high-performance Python engine designed for **External Attack Surface Management (EASM)**, **Active & Passive Asset Reconnaissance**, and **Vulnerability Weaponization Intelligence**. It maps exposed internet infrastructure, performs targeted vulnerability validation, and enriches findings with real-world exploitation risk data (FIRST EPSS + CISA KEV).

---

## 📦 Quick Installation

```bash
# 1. Download and install from PyPI
pip install detecti-cli

# 2. Run the automated setup routine
detecti-cli config-check --setup

# 3. Explore commands
detecti-cli --help
```

*For prerequisites like Masscan and Nuclei, and advanced API keys configuration, check the [Installation Guide](https://detecti.com.br/docs/detecti-cli/en.html#setup-install).*

---

## 💻 CLI Usage Examples

```bash
# Recon a single IP or CIDR Subnet
detecti-cli recon 142.250.191.68
detecti-cli recon 142.250.191.0/24

# Recon a Domain (Subdomains + Reverse WHOIS + Infrastructure)
detecti-cli recon spacex.com

# Recon a Batch Target List from File
detecti-cli recon targets.txt

# Fetch Threat Intelligence for a specific CVE
detecti-cli intel CVE-2021-44228

# Start the Interactive EASM Web Dashboard (DetecTIHound)
detecti-cli hound start
```

*For advanced queries, vulnerability filtering, and reporting, see the [CLI Usage Guide](https://detecti.com.br/docs/detecti-cli/en.html#cli-quickstart).*

---

## 🏗️ Architecture

```
DetecTI-CLI/
├── pyproject.toml           # Modern Packaging & Dependency Definition
├── README.md                # Project Overview
├── detecti/                 # Main Application Package
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
│   │   ├── masscan.py       # High-Speed Active Port Scanner
│   │   ├── nuclei.py        # Asynchronous Nuclei Vulnerability Scanner Engine
│   │   ├── nvd.py           # NVD 2.0 (CVSS/CWE) + EPSS Probability + CISA KEV
│   │   └── exploitdb.py     # ExploitDB (searchsploit) & GitHub PoC Collector
│   ├── reporters/           # Report Generation Subsystem (CSV, HTML, JSON, Markdown)
│   ├── web/                 # Interactive EASM Dashboard Subsystem
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
<sub>Developed for <b><a href="https://detecti.com.br" target="_blank">DetecTI Security</a></b></sub>

Feel free to open Issues or submit Pull Requests to contribute!
