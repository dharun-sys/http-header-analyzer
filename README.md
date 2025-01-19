# HTTP Header Analyzer

`HTTP Header Analyzer` is a Python tool designed to analyze HTTP response headers for potential security issues, server information, SSL/TLS configurations, and other critical details. This tool provides insights into the presence or absence of important security headers and identifies potential information disclosure.

---

## Features

- **Security Header Analysis**:
  - Detects missing security headers such as:
    - `Strict-Transport-Security` (HSTS)
    - `X-Frame-Options`
    - `X-Content-Type-Options`
    - `Content-Security-Policy`
    - `Referrer-Policy`
    - `Permissions-Policy`
    - `Cross-Origin` headers (COEP, COOP, CORP)
- **Server Information Disclosure**:
  - Identifies headers like `Server`, `X-Powered-By`, etc., that may reveal sensitive backend technology.
- **SSL/TLS Validation**:
  - Fetches SSL/TLS certificate details (only for HTTPS URLs).
  - Displays the SSL version and certificate expiration date.
- **Response Headers Display**:
  - Outputs all response headers received from the target URL.
- **JSON Report**:
  - Saves the response headers to a `headers.json` file for further analysis.

---

## Installation

Follow these steps to set up and run the HTTP Header Analyzer tool on your system:

---

## Prerequisites

- Python 3.x installed on your system
- `pip` package manager (comes pre-installed with Python)

---

## Steps

### 1. Clone or Download the Repository
Clone the repository using Git or download it as a ZIP file and extract it.

```bash
git clone https://github.com/dharun-sys/http-header-analyzer.git
cd http-header-analyzer

```
Install requirements

```bash
pip install requirements.txt
```
Usage
```bash
python3 header_analyzer.py https://www.example.com
```
### License

This project is licensed under the [MIT License](LICENSE).
