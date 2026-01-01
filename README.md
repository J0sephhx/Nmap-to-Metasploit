# Nmap XML → Metasploit RC Generator

Repository contents: a Python tool that parses Nmap XML output and generates a safe Metasploit resource script (.rc). The tool focuses on enumeration and safe checks only (anonymous FTP, banner grabs, SMB listing, etc.). It also supports dry-run, reports in multiple formats, optional LLM integration for suggestions, interactive review, and a Docker-compose lab generator for local testing.

---

## Features

* Parse Nmap XML (-oX) and extract hosts, ports and services.
* Map detected services to safe Metasploit auxiliary/scanner modules via a YAML mapping file.
* Safety levels: `safe`, `extended`, `bruteforce` (default: `safe`).
* Generate a Metasploit resource script (.rc) with `use`, `set`, and `run -j` commands.
* Optional `db_import` of the Nmap XML and optional workspace creation.
* Dry-run mode to list planned modules without writing files.
* Optional LLM integration (OpenAI / Gemini) to suggest additional modules and provide commentary (returns JSON).
* Multi-format reporting: JSON, Markdown, DOCX, PDF.
* Interactive CLI review mode to accept/reject modules.
* Docker Compose template generator for a small vulnerable lab (for safe testing only).

---

## Warning & Legal / Safety

This tool is intended for **authorized security testing, training, and educational use only**. Do not run it against systems you do not own or do not have explicit permission to test. The default safety level is `safe` and the mapping is designed to avoid destructive exploits. Brute-force or intrusive modules are categorized under `bruteforce` and will only be included when the user explicitly selects that safety level.

Always get written authorization before testing third-party networks or systems.

---

## Quick start

1. Create a Python virtual environment and install dependencies (see `requirements.txt`).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Run an Nmap scan and save XML output:

```bash
nmap -sV -oX nmap_scan.xml 192.168.56.0/24
```

3. Generate a .rc script from the scan:

```bash
python3 nmap_to_ms.py -i nmap_scan.xml -o generated.rc --import-xml --workspace mylab
```

4. Dry-run (no file written):

```bash
python3 nmap_to_ms.py -i nmap_scan.xml --dry-run
```

5. Interactive review before generating:

```bash
python3 nmap_to_ms.py -i nmap_scan.xml --interactive
```

---

## CLI usage and options

```
usage: nmap_to_ms.py [-h] -i INPUT [-o OUTPUT] [-t TARGET] [-c CONFIG] [-w WORKSPACE]
                     [--import-xml] [--dry-run] [--llm-api-key LLM_API_KEY]
                     [--report REPORT] [--markdown-report MARKDOWN_REPORT]
                     [--docx-report DOCX_REPORT] [--pdf-report PDF_REPORT]
                     [--interactive] [--safety-level {safe,extended,bruteforce}]
                     [--setup-docker-lab]
```

Key flags explained:

* `-i, --input`: Nmap XML file generated with `-oX` (required).
* `-o, --output`: Output RC file (default: `generated.rc`).
* `-t, --target`: Only process the specified IPv4 address from the XML.
* `-c, --config`: Path to YAML service->module mapping file (default: `service_module_mapping.yaml`).
* `--import-xml`: Add `db_import <file>` to the generated RC so Metasploit imports the Nmap data.
* `--dry-run`: Print the planned modules to stdout but do not write files.
* `--llm-api-key`: Optional API key for LLM suggestions (OpenAI/Gemini). When provided, the tool will call the selected provider and expect a JSON array response with `module`, `description`, and `commentary` fields.
* `--report`: Generate a JSON report of the mapping plan.
* `--markdown-report`, `--docx-report`, `--pdf-report`: Generate reports in other formats.
* `--interactive`: Enter interactive review to accept/reject modules before generation.
* `--safety-level`: Set desired safety level (`safe`, `extended`, `bruteforce`). Default: `safe`.
* `--setup-docker-lab`: Write a `docker-compose.yml` with vulnerable service images for local testing.

---

## service_module_mapping.yaml (default behavior)

The tool ships with a default YAML mapping file (`service_module_mapping.yaml`) created the first time it runs. It includes safe enumerators for common services (SSH, HTTP/HTTPS, FTP, SMB, SNMP, Telnet, SMTP, MySQL, MSSQL, Oracle). You may edit or extend this file to add or tune module mappings.

Example entry (already created by default):

```yaml
services:
  http:
    - module: auxiliary/scanner/http/http_title
      description: Get HTTP title
      safety_level: safe
    - module: auxiliary/scanner/http/dir_scanner
      description: Directory scanner
      safety_level: extended
      options:
        PATH: /
```

---

## LLM Integration (optional)

If you provide `--llm-api-key`, the tool attempts to detect provider from the key and query the LLM for JSON-formatted suggestions. The script expects the model to return a JSON array like:

```json
[
  {"module": "auxiliary/scanner/http/http_title", "description": "Get HTTP title", "commentary": "Safe enumeration step"}
]
```

**Important**: LLM integration is optional and the tool will not rely on it. Always validate suggested modules before running them against a target.

---

## Contributing and extending

* Edit or extend `service_module_mapping.yaml` to add additional mappings.
* Add more report formats by following existing report generator functions.
* Improve LLM prompt handling and validation to harden against unexpected outputs.

---

## License

This project is provided for educational purposes. Check with your institution for permitted use.
