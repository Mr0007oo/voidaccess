# VoidAccess

A self-hosted OSINT platform for dark web threat intelligence. It automates the entire investigation workflow from query to graph in 13 pipeline steps.

![Dashboard](docs/screenshots/dashboard.png)

![Entity Graph](docs/screenshots/entity-graph.png)

---

## What This Is

Commercial threat intelligence platforms charge $8,000 to $25,000 per year for capabilities you can run on your own hardware. VoidAccess automates the dark web OSINT workflow: query refinement, multi-engine searching over Tor, content scraping, entity extraction, relationship mapping, and structured export.

This is for SOC analysts hunting infrastructure, threat intelligence researchers tracking actor operations, security engineers building detection content, and law enforcement conducting authorized investigations. If you know what OSINT is, you know why this exists.

---

## How It Works

You enter a query, and the investigation runs through 13 pipeline steps:

1. The LLM refines your query into terms optimized for dark web search engines.
2. Search fans out to 16+ Tor-based search engines across multiple languages (English, Russian, Chinese).
3. Results are filtered by relevance using the LLM, keeping only intelligence-bearing pages.
4. Threat intel enrichment pulls data from AlienVault OTX, abuse.ch feeds, ransomware.live, CISA KEV, and Shodan.
5. The recursive crawler discovers additional .onion pages from seed URLs.
6. A 24-hour vector cache lookup avoids re-scraping recently visited URLs.
7. Fresh pages are scraped over Tor with a 1MB cap per page.
8. Scraped content is stored in the vector cache for future searches.
9. Merged pages (enrichment + scraped) are processed for entity extraction.
10. Regex, NER, and LLM extraction identify all indicators from each page.
11. Extracted entities are cross-referenced against historical seed data.
12. The relationship graph is built from entity co-occurrence.
13. The LLM generates a threat intelligence summary.

```
Query → LLM Refine → Tor Search Fan-out → LLM Filter
        ↓
Enrichment (AlienVault OTX, abuse.ch, ransomware.live, CISA KEV, Shodan)
        ↓
Crawler (recursive .onion discovery) → Vector Cache (24h lookup)
        ↓
Scrape (1MB cap per page over Tor) → Store in vector cache
        ↓
Entity Extract (regex, NER, LLM) → Cross-Ref → Graph Build → Summary
        ↓
Export: STIX | MISP | Sigma | CSV
```

---

## What It Extracts

The extractor identifies these entity types:

- **Cryptocurrency**: Bitcoin, Ethereum, Monero wallet addresses
- **Network Indicators**: IPv4, Onion URLs, domains, email addresses, PGP keys/blocks
- **File Indicators**: MD5, SHA1, SHA256 hashes
- **Vulnerabilities**: CVE numbers, MITRE ATT&CK techniques
- **Threat Actors**: Actor handles, malware families, ransomware groups
- **Paste Sites**: Links to Pastebin, Ghostbin, Rentry, and similar
- **People/Orgs**: Named persons, organization names, locations

Enrichment sources (8 total):

- **AlienVault OTX** — threat pulses and malware families
- **MalwareBazaar** — malware samples and signatures
- **ThreatFox** — recent IOC feed
- **URLhaus** — malicious URL database
- **ransomware.live** — ransomware group tracking
- **CISA KEV** — known exploited vulnerabilities catalog
- **Shodan InternetDB** — vulnerability signatures
- **VirusTotal** — file/reputation enrichment (API key required)

Export formats:

- STIX 2.1 (bundles with indicators, threat actors, malware)
- MISP JSON (events with galaxies)
- Sigma rules (auto-generated from IOCs)
- CSV (entity dumps)

---

## Quick Start

Prerequisites: Docker, Docker Compose, a Tor-capable network, and at least one LLM API key.

Free LLM options:

- Groq: free tier, fast inference
- OpenRouter: free tier via Llama 3.3 70B
- Google Gemini: free tier via AI Studio
- Ollama: runs locally, no API key needed

Installation:

```bash
cp .env.example .env
bash setup.sh
```

The setup wizard prompts for your LLM provider choice, generates secrets, and starts the Docker stack.

Getting a JWT (login):

```bash
# Login to get JWT token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "password": "yourpassword"}'
```

Use the returned token in the Authorization header for subsequent requests.

Running your first investigation:

```bash
curl -X POST http://localhost:8000/investigations \
  -H "Authorization: Bearer <your_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"query": "LockBit ransomware infrastructure 2024"}'
```

What you see: the investigation starts in "pending", flips to "processing", and after 3-5 minutes completes with a summary, extracted entities (wallets, C2 IPs, onion URLs, actor handles), a relationship graph showing how they connect, and export options in STIX/MISP/Sigma/CSV formats.

---

## LLM Support

VoidAccess supports these providers:

- OpenRouter (DeepSeek, Llama 3.3, Claude Haiku, Gemini 2.0)
- Groq (Llama 3.3, Llama 3.1)
- OpenAI (GPT-4o Mini)
- Anthropic (Claude Haiku, Sonnet)
- Google Gemini (Gemini 1.5 Flash, Gemini 2.5 Pro)
- Ollama (local, no API key)

The default is DeepSeek via OpenRouter because it's cheap (under $0.50 per investigation), fast, and good at technical security content. If you need an air-gapped setup, Ollama runs entirely locally with no API key required.

---

## Content Filtering

Every investigation runs through mandatory content safety filters before results reach you or appear in the graph. CSAM, gore, snuff content, and other prohibited material are blocked at the query stage, URL validation, content scanning, and post-extraction entity filtering. This is not optional and cannot be disabled.

---

## Cost

| Platform | Annual Cost | Open Source | Self-Hosted |
|----------|-------------|-------------|-------------|
| Recorded Future | ~$25,000 | No | No |
| DarkOwl | ~$15,000 | No | No |
| Flare | ~$8,000 | No | No |
| VoidAccess | Free | Yes | Yes |

Under $10 for 100 investigations using free-tier LLMs.

---

## Architecture

Four Docker services run the stack:

- **postgres** — PostgreSQL 16 for investigation records, entities, graph data
- **tor** — Tor SOCKS5 proxy for all .onion requests
- **fastapi** — Python backend handling pipeline, extraction, graph, export
- **nextjs** — Next.js 14 frontend with Tailwind

Backend: Python 3.11, FastAPI, SQLAlchemy, PostgreSQL, Redis, NetworkX

Frontend: Next.js 14, TypeScript, Tailwind CSS, sigma.js for graph rendering

---

## Acceptable Use

VoidAccess is for authorized security research, threat intelligence gathering, and law enforcement purposes only. Do not use it to target individuals, facilitate attacks, or access systems without authorization. If you're unsure whether your use is authorized, it probably isn't.

---

## Contributing

Contributions are welcome. See CONTRIBUTING.md for guidelines.

---

## License

MIT License. See LICENSE file for details.