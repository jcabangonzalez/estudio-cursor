# LogSec Toolkit

Defensive log analysis CLI for Apache access logs and OWASP Juice Shop docker logs.
Combines rule-based threat detection with AI-powered analysis (Claude + Gemini fallback).

## Features
- Apache/Nginx access log parsing
- Top IP detection and traffic analysis
- 4xx / 5xx error tracking
- Brute-force login detection
- Vulnerability scanner detection
- Flood/DDoS pattern detection
- Unified risk scoring per IP (LOW / MEDIUM / HIGH / CRITICAL)
- AI-powered security report via Claude API (Gemini fallback)

## Setup
pip install anthropic google-genai python-dotenv requests
Create .env with ANTHROPIC_API_KEY and GEMINI_API_KEY

## Usage
PYTHONPATH=logsec-toolkit/src python3 -m logsec apache logsec-toolkit/samples/access.log

## Stack
- Python 3.10+
- Anthropic Claude API (claude-haiku-4-5)
- Google Gemini API (fallback)
- argparse, collections, re, dotenv
