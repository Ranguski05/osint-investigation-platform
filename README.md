OSINT Investigation Platform

Overview

A modular, portfolio-level OSINT Investigation Platform designed to collect, normalize, correlate, and visualize publicly available intelligence from multiple independent collectors.

The platform uses a collector-based architecture where each collector gathers information about an investigation target and produces structured observations, relationships, metadata, and evidence.

Current Status

The first complete vertical slice of the platform is implemented.

Implemented:
• DNS intelligence collector
• Structured DNS observation models
• A, AAAA, CNAME, MX, NS, TXT, SOA, CAA and DNSSEC-related record collection
• Configurable DNS resolvers and timeouts
• Per-query timing and status tracking
• Structured error handling
• Related entity extraction
• JSON investigation output
• FastAPI investigation API
• React + TypeScript + Vite frontend
• Live target querying
• Interactive 3D investigation graph
• Automatic graph layout and camera fitting
• Entity-type visualization
• Node highlighting and glow effects
• Node inspection
• Query performance visualization
• Investigation status and metadata panels
• Atmospheric 3D globe background
• Glass-style UI

Architecture

Investigation Target
        ↓
DNS Collector
        ↓
Structured Observations
        ↓
FastAPI Investigation API
        ↓
React + TypeScript Frontend
        ↓
3D Investigation Graph

Project Structure

osint-investigation-platform/
├── backend/          FastAPI investigation API
├── collectors/
│   └── dns/          DNS collector
├── frontend/         React + TypeScript dashboard
├── tests/            Collector tests
├── pyproject.toml
├── requirements.txt
├── package-lock.json
├── .gitignore
└── README.md

DNS Collector

The DNS collector is the first production-oriented collector in the platform.

It accepts targets such as domains and produces structured JSON containing target information, collection timestamps, collector metadata, DNS records, related entities, resolver information, query duration, query status, and collection errors.

Example:
python -m collectors.dns example.com --json --nameserver 8.8.8.8

Investigation Graph

The frontend converts collector output into an interactive 3D investigation graph.

The graph represents relationships between domains, hostnames, IP addresses, nameservers, mail servers, organizations, certificates, and other discovered entities.

The graph is completely data-driven and is not tied to a specific domain.

Running the Project

Create and activate the Python environment:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

Install dependencies:
pip install -r requirements.txt

Start the backend:
python -m uvicorn backend.main:app --reload --port 8000

Start the frontend in another terminal:
cd frontend
npm install
npm run dev

Backend API: http://localhost:8000
FastAPI documentation: http://localhost:8000/docs
Frontend: http://localhost:5173

Roadmap

Collectors
✓ DNS collector
□ Subdomain enumeration
□ RDAP / WHOIS collector
□ Certificate Transparency collector
□ HTTP / HTTPS collector
□ IP intelligence collector
□ Email intelligence collector
□ Username intelligence collector
□ Organization intelligence collector

Core Platform
✓ Structured collector output
✓ Related entity extraction
✓ Investigation API
□ PostgreSQL persistence
□ Evidence and provenance storage
□ Central correlation engine
□ Investigation history
□ Cross-collector entity correlation
□ Persistent investigation graph

Intelligence Layer
□ Automated correlation
□ Entity confidence scoring
□ Evidence ranking
□ Timeline generation
□ AI-assisted investigation
□ Natural-language investigation interface

Design Principles

Modularity: Collectors operate independently and produce standardized observations.

Evidence Preservation: Collected information should retain timestamps, source information, query status, and provenance.

Data-Driven Visualization: The frontend visualizes investigation data dynamically rather than relying on hardcoded domains or relationships.

Failure Transparency: Partial collection failures are represented explicitly rather than silently discarded.

Extensibility: New collectors and entity types should be possible without redesigning the entire platform.

Disclaimer

This project is intended for educational, research, and authorized OSINT investigations.

Only investigate systems, domains, accounts, and infrastructure that you are authorized to investigate or that are appropriate for legitimate public-information research.