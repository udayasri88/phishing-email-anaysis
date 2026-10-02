# Phishing Email Analysis & Detection Pipeline

A home-lab SOC project that simulates an end-to-end phishing detection workflow — from email delivery, through header/IOC analysis, to SIEM correlation, alerting, and dashboarding in Splunk.

This project is designed to mirror the daily triage work of a **SOC L1 analyst**: receiving a suspicious email, analyzing its headers and content, enriching indicators with threat intelligence, and feeding the results into a SIEM for detection and reporting.

---

## Architecture

```
Linux Lite (Attacker)
   → crafts & sends phishing email (swaks / Python smtplib)
        ↓
Mail Server (hMailServer / Postfix) (Linux Mint)
   → relays & delivers email, logs SMTP transaction
        ↓
Windows VM (Victim)
   → Thunderbird receives email, saved as .eml
        ↓
Kali Linux (Analysis + SIEM)
   → phish_parser.py extracts headers, URLs, attachment hashes
   → enriches IOCs via VirusTotal & AbuseIPDB APIs
   → outputs structured JSON report
        ↓
Splunk (on Kali)
   → ingests mail logs + IOC JSON reports
   → detection rules (SPL) flag malicious indicators
   → dashboard visualizes phishing trends
```

**Lab environment:** 4 VirtualBox VMs (Kali, Windows, Linux Mint/Windows 7, Linux Lite) networked together to simulate a realistic attacker → mail server → victim → SOC pipeline.

---

## What This Project Covers

- **Email header analysis** — SPF, DKIM, DMARC results; Return-Path vs From mismatches; Received-header hop tracing
- **URL & attachment analysis** — extraction and reputation checks via VirusTotal and URLScan.io
- **IOC extraction & automation** — a Python script that parses raw `.eml` files and outputs structured IOC data
- **Threat intelligence enrichment** — VirusTotal (URL/hash reputation) and AbuseIPDB (sender IP reputation)
- **SIEM correlation** — ingesting mail server logs and IOC reports into Splunk
- **Detection engineering** — SPL queries to flag phishing indicators (SPF fail + malicious verdict, mass-phishing waves, known-bad senders)
- **Dashboarding** — visual overview of phishing attempts, verdicts, and top offenders
- **Incident response playbook** — documented triage → contain → notify → document workflow

---

## Tools & Technologies

| Category | Tool |
|---|---|
| SIEM | Splunk |
| Mail server | hMailServer / Postfix |
| Mail client | Thunderbird |
| Scripting | Python 3 (`email`, `hashlib`, `requests`) |
| Threat intel | VirusTotal API, AbuseIPDB API |
| Email crafting | swaks / Python `smtplib` |
| Virtualization | Oracle VirtualBox (Kali, Windows, Linux Mint, Linux Lite) |

---

## Repository Structure

```
phishing-detection-pipeline/
├── README.md
├── scripts/
│   └── script.py          # Parses .eml files, extracts & enriches IOCs
├── samples/
│   └── sample_phishing.eml      # Sanitized lab-generated phishing sample
├── reports/
│   └── sample_ioc_report.json   # Example script output
├── splunk/
│   ├── spl_queries.txt          # Detection search queries used
│   └── dashboard_screenshots/   # Dashboard panel screenshots
├── analysis/
│   └── sample_analysis_writeup.md   # Manual header/IOC analysis walkthrough
└── playbook/
    └── incident_response_playbook.md
```

---

## How It Works

1. **Email delivery (simulated attack):** A phishing email with a spoofed sender and suspicious link is sent from the attacker VM through the mail server to the victim's Thunderbird inbox.
2. **Manual triage:** The raw email is saved as `.eml` and manually reviewed — header anomalies, SPF/DKIM/DMARC results, and link structure are documented.
3. **Automated IOC extraction:** `phish_parser.py` parses the `.eml` file, extracts headers/URLs/attachment hashes, and queries VirusTotal and AbuseIPDB for reputation data. Output is written as structured JSON.
4. **SIEM ingestion:** Mail server logs and IOC JSON reports are ingested into Splunk.
5. **Detection & alerting:** SPL searches flag high-risk indicators (e.g., SPF fail + malicious VirusTotal verdict), and a Splunk alert fires on match.
6. **Dashboarding:** A Splunk dashboard visualizes phishing attempts over time, verdict breakdown, top sender domains, and flagged IOCs.
7. **Response:** A documented (and partially automated) playbook covers triage, containment, notification, and reporting.

---

## Sample Detection Logic

```spl
index=phishing vt_verdict="malicious" spf_result="fail"
| table _time, sender, urls_found, sender_ip, abuseipdb_score, vt_verdict
```

See `splunk/spl_queries.txt` for the full set of detections used in this lab (mass-phishing wave detection, SPF/DKIM fail rate, known-bad IP matches).

---

## Dashboard

The Splunk dashboard includes:
- Phishing attempts over time
- Verdict breakdown (malicious / suspicious / clean)
- SPF/DKIM/DMARC fail rate
- Top sender domains and targeted recipients
- IOC reference table (URLs, hashes, reputation scores)
- KPI panels (total analyzed, total malicious, top offending IP)

Screenshots available in `splunk/dashboard_screenshots/`.

---

## Key Takeaways / Lessons Learned

- SPF/DKIM/DMARC failures alone aren't sufficient to confirm phishing — correlating header anomalies with threat intel verdicts significantly reduces false positives.
- Automating IOC extraction turns a one-off manual review into a repeatable, scalable triage process — the kind of workflow real SOC teams rely on.
- Structuring script output as JSON made Splunk ingestion and field extraction far simpler than feeding in raw `.eml` files.
- Building the attacker → mail server → victim chain end-to-end (rather than using only pre-downloaded samples) gave a much more realistic picture of how phishing indicators actually propagate through logs.

---

## Disclaimer

This project was built entirely in an isolated home lab for educational purposes. No real phishing campaigns, real malicious payloads, or real victims were involved. All `.eml` samples in this repository are lab-generated and sanitized.

---

## Author

Built as part of a self-directed SOC Analyst (L1) portfolio, alongside a Windows Security Monitoring & Brute-Force Detection project (Splunk).
