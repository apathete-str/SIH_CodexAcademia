# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

A cloud-deployed, Python-based security platform that ingests emails (primarily via MTA integration), parses and enriches them, runs AI threat detection, maps sender/infrastructure geo-intelligence, and packages everything into court-ready forensic case files.

## Architecture

```
┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────────────┐
│  INGESTION  │──▶│   PARSING    │──▶│  ENRICHMENT  │──▶│  AI DETECTION │
│ MTA/IMAP/   │   │  Normalize   │   │ URL/IP/Domain│   │  Threat Score │
│ Upload/API  │   │  EML→Canonical│  │ Attachment   │   │  Explainable  │
└─────────────┘   └──────────────┘   └──────────────┘   └───────┬───────┘
                                                                │
┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────▼───────┐
│  DASHBOARD  │◀──│  RESPONSE    │◀──│  FORENSICS   │◀──│  GEOLOCATION  │
│ React/Next  │   │  Quarantine/ │   │  Case Mgmt   │   │  IP/Infra Map │
│  Analytics  │   │  Alert/Block │   │  Chain-of-   │   │  Threat Actor │
│             │   │              │   │  Custody     │   │  Attribution  │
└─────────────┘   └──────────────┘   └──────────────┘   └───────────────┘
```

## Tech Stack
- **Backend:** Python 3.11, FastAPI, Celery, Redis, PostgreSQL, Qdrant
- **ML:** scikit-learn, HuggingFace transformers, spaCy, PyTorch
- **Parsing:** mailparser, extract-msg, stdlib email
- **Enrichment:** VirusTotal, urlscan.io, Google Safe Browsing, MaxMind GeoIP2, python-whois, dnspython
- **Frontend:** React + Next.js, Recharts/D3
- **Infra:** Docker, Docker Compose, AWS

## Quick Start (dev)
```bash
docker compose up --build
# Backend: http://localhost:8000/docs
# Frontend: http://localhost:3000
```

## Project Structure
```
backend/          FastAPI application
  app/
    models/       Pydantic schemas
    ingest/       Ingestion connectors
    parse/        Parsing & normalization
    enrich/       Enrichment providers
    detect/       AI threat detection
    geo/          GeoLocation intelligence
    forensic/     Forensic & case management
    api/          REST API routers
frontend/         Next.js dashboard
ml/               Training notebooks & model registry
infra/            Docker & deployment config
```
