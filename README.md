OSINT Investigation Platform

A modular, portfolio-level OSINT Investigation Platform designed to collect, normalize, correlate, and visualize publicly available intelligence from multiple independent collectors.

The platform is being built around a collector-based architecture where each collector gathers information about an investigation target and produces structured observations, relationships, metadata, and evidence.

Current Status

The first complete vertical slice of the platform is implemented.

Implemented
DNS intelligence collector
Structured DNS observation models
DNS record collection:
A
AAAA
CNAME
MX
NS
TXT
SOA
CAA
DNSSEC-related records
Configurable DNS resolvers
Configurable query timeouts
Per-query timing and status tracking
Structured error handling
Related entity extraction
JSON investigation output
FastAPI investigation API
React + TypeScript + Vite frontend
Live target querying
Interactive 3D investigation graph
Automatic graph layout and camera fitting
Entity-type visualization
Node highlighting and glow effects
Node inspection
Query performance visualization
Investigation status and metadata panels
Atmospheric 3D globe background
Glass-style investigation UI
Architecture
                    Investigation Target
                            |
                            v
                  +-------------------+
                  |   DNS Collector   |
                  +-------------------+
                            |
                            v
                  +-------------------+
                  | Structured Output |
                  |   Observations    |
                  +-------------------+
                            |
                            v
                  +-------------------+
                  |    FastAPI API    |
                  +-------------------+
                            |
                            v
                  +-------------------+
                  | React + TypeScript|
                  | Investigation UI  |
                  +-------------------+
                            |
                            v
                  +-------------------+
                  | 3D Investigation  |
                  |      Graph        |
                  +-------------------+
Project Structure
osint-investigation-platform/
│
├── backend/
│   └── FastAPI investigation API
│
├── collectors/
│   └── dns/
│       ├── collector.py
│       ├── resolver.py
│       ├── models.py
│       ├── exceptions.py
│       └── utils.py
│
├── frontend/
│   └── React + TypeScript + Vite investigation dashboard
│
├── tests/
│   └── collectors/
│       └── dns/
│
├── pyproject.toml
├── requirements.txt
├── package-lock.json
├── .gitignore
└── README.md
DNS Collector

The DNS collector is the first production-oriented collector in the platform.

It accepts investigation targets such as domains and produces structured JSON containing:

Target information
Collection timestamp
Collector metadata
DNS records
Related entities
Resolver information
Query duration
Query status
Collection errors

Example:

python -m collectors.dns example.com --json --nameserver 8.8.8.8

The collector supports configurable resolvers and timeout settings.

Investigation Graph

The frontend converts collector output into an interactive 3D investigation graph.

The graph represents relationships between entities such as:

Domains
Hostnames
IP addresses
Nameservers
Mail servers
Organizations
Certificates
Other discovered entities

The graph is completely data-driven and is not tied to a specific domain.

For example:

             Nameserver
                  |
                  | NS
                  |
                  v
IP Address <-- Domain --> Mail Server
     |            |
     | A/AAAA     | TXT/MX/NS
     |            |
     v            v
 Related       Related
 Entity        Entity
Frontend

The investigation dashboard currently provides:

Target search
Live DNS investigations
Investigation status
Interactive 3D graph
Entity-type visualization
Node highlighting
Node selection and inspection
Query performance information
DNS record inspection
Related entity inspection
Graph camera controls
Automatic graph fitting
Atmospheric globe visualization
Glass-style UI panels
Running the Project
Install Python dependencies

Create and activate the virtual environment:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt
Start the backend

From the project root:

python -m uvicorn backend.main:app --reload --port 8000

The API will be available at:

http://localhost:8000

FastAPI documentation:

http://localhost:8000/docs
Start the frontend

In another terminal:

cd frontend
npm install
npm run dev

The frontend will normally be available at:

http://localhost:5173
Example Investigation

A DNS investigation can be performed directly through the collector:

python -m collectors.dns example.com --json --nameserver 8.8.8.8

Alternatively, targets can be entered directly into the frontend investigation search interface.

The collected data is passed through the API and transformed into the interactive investigation graph.

Roadmap
Collectors
 DNS collector
 Subdomain enumeration
 RDAP / WHOIS collector
 Certificate Transparency collector
 HTTP / HTTPS collector
 IP intelligence collector
 Email intelligence collector
 Username intelligence collector
 Organization intelligence collector
Core Platform
 Structured collector output
 Related entity extraction
 Investigation API
 PostgreSQL persistence
 Evidence and provenance storage
 Central correlation engine
 Investigation history
 Cross-collector entity correlation
 Persistent investigation graph
Intelligence Layer
 Automated correlation
 Entity confidence scoring
 Evidence ranking
 Timeline generation
 AI-assisted investigation
 Natural-language investigation interface
Design Principles
Modularity

Collectors operate independently and produce standardized observations.

Evidence Preservation

Collected information should retain metadata such as timestamps, source information, query status, and provenance.

Data-Driven Visualization

The frontend visualizes investigation data dynamically rather than relying on hardcoded domains or relationships.

Failure Transparency

Partial collection failures are represented explicitly rather than silently discarded.

Extensibility

New collectors and entity types should be possible without requiring a redesign of the entire platform.

Disclaimer

This project is intended for educational, research, and authorized OSINT investigations.

Only investigate systems, domains, accounts, and infrastructure that you are authorized to investigate or that are appropriate for legitimate public-information research