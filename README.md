# ReconX Subdomains

ReconX Subdomains is a reconnaissance-focused subdomain enumeration engine designed for offensive security operations, attack surface intelligence, and large-scale asset discovery workflows.

The project was built to solve a common problem in modern reconnaissance:

single-source enumeration produces incomplete visibility.

ReconX Subdomains aggregates intelligence from multiple passive collection sources, DNS bruteforce pipelines, recursive discovery techniques, permutation-based expansion, and validation stages to maximize subdomain coverage while maintaining clean and reliable output.

Rather than functioning as a thin wrapper around existing tools, the engine focuses on orchestration, normalization, enrichment, validation, and intelligent expansion of reconnaissance data.

---

# Core Capabilities

## Multi-Source Enumeration Pipeline

ReconX Subdomains integrates passive intelligence from multiple external data providers and reconnaissance tools to improve discovery coverage and reduce source bias.

Supported integrations include:

* subfinder
* amass
* assetfinder
* crt.sh
* CertSpotter
* VirusTotal
* AlienVault OTX
* URLScan
* RapidDNS
* BufferOver
* DNSDumpster
* HackerTarget
* gau
* Wayback Machine
* GitHub code search
* jldc.me / Anubis datasets

The engine normalizes and merges all collected intelligence into a unified enumeration pipeline.

---

# DNS Bruteforce & Expansion

Passive enumeration alone often misses internal naming conventions, development environments, staging infrastructure, legacy hosts, and ephemeral assets.

ReconX Subdomains includes:

* high-speed DNS bruteforce using dnsx
* threaded resolver fallback systems
* intelligent subdomain mutation generation
* environment-aware permutations
* recursive expansion techniques
* validation and deduplication stages

The permutation engine dynamically generates infrastructure-oriented naming candidates such as:

* api-dev
* staging-admin
* internal-app
* beta-v2
* legacy-prod

This significantly improves discovery of operational infrastructure that is not publicly indexed.

---

# Validation Pipeline

Enumeration quality is often limited by noise, wildcard responses, duplicate data, and stale intelligence.

ReconX Subdomains performs multiple cleanup stages including:

* regex-based normalization
* wildcard cleanup
* duplicate removal
* DNS validation
* invalid hostname filtering
* malformed asset rejection

The goal is to produce reconnaissance output that is operationally useful rather than simply high-volume.

---

# Engineering Design

The project was engineered around several reconnaissance principles:

* source diversity over source dependency
* validation over raw volume
* modular discovery pipelines
* reusable reconnaissance components
* scalable enumeration workflows
* low-friction automation
* operator-friendly output

The architecture intentionally separates:

* discovery
* validation
* expansion
* orchestration

to support future modularization and distributed reconnaissance workflows.

---

# Operational Workflow

```text
Passive Collection
        ↓
Source Aggregation
        ↓
Normalization & Deduplication
        ↓
DNS Bruteforce
        ↓
Permutation Expansion
        ↓
Parallel Resolution
        ↓
Validation Pipeline
        ↓
Final Attack Surface Dataset
```

---

# Why ReconX Subdomains Exists

Most enumeration tooling focuses exclusively on collection.

ReconX Subdomains focuses on:

* aggregation quality
* operational usefulness
* discovery expansion
* validation accuracy
* workflow integration

The engine was designed to function as part of larger offensive security pipelines including:

* attack surface mapping
* bug bounty reconnaissance
* external asset intelligence
* red team infrastructure discovery
* continuous reconnaissance workflows

---

# Installation

## Clone Repository

```bash
git clone https://github.com/msk0x/reconx-subdomains.git
cd reconx-subdomains
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Recommended External Tooling

ReconX Subdomains integrates with several open-source reconnaissance tools including:

* subfinder
* amass
* dnsx
* gau
* waybackurls
* assetfinder

Installing these tools significantly improves enumeration coverage and performance.

---

# Usage

## Basic Enumeration

```bash
python3 main.py -d example.com
```

---

## Enumeration With Bruteforce

```bash
python3 main.py -d example.com --bruteforce
```

---

## Custom DNS Wordlist

```bash
python3 main.py -d example.com --wordlist wordlists/dns.txt
```

---

# Example Output

```text
api.example.com
dev.example.com
staging.example.com
internal.example.com
admin.example.com
cdn.example.com
```

---

# Performance Notes

Enumeration quality and speed depend on:

* installed tooling
* API availability
* resolver quality
* network conditions
* target size
* DNS response behavior

Using:

* subfinder
* dnsx
* amass
* gau

provides the best overall performance and coverage.

---

# Security & Legal Notice

This project is intended exclusively for:

* authorized security testing
* bug bounty programs
* defensive research
* attack surface analysis
* infrastructure visibility

Users are responsible for ensuring compliance with:

* applicable laws
* target authorization requirements
* API provider terms
* rate limits
* organizational policies

Unauthorized use against systems without permission is prohibited.

---

# Third-Party Tooling & Attribution

ReconX Subdomains integrates with multiple third-party open-source reconnaissance tools and data providers.

All external tools, trademarks, and associated projects remain the property of their respective maintainers and communities.

This repository primarily provides orchestration, aggregation, validation, and workflow logic around those ecosystems.

---

# License

MIT License

This project is released under the MIT License.

You are permitted to:

* use
* modify
* distribute
* extend
* integrate

the software while retaining the original license and attribution notice.

---

# Future Development

Planned improvements include:

* asynchronous enumeration architecture
* plugin-based source loading
* distributed resolver pools
* ASN-based expansion
* recursive brute-force workflows
* resolver reputation scoring
* API export modes
* Docker deployment support
* distributed reconnaissance orchestration

---

# Acknowledgements

Respect to the open-source offensive security and reconnaissance community whose tooling, research, and methodologies continue to advance attack surface intelligence and defensive visibility across the industry.
