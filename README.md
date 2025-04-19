# ProcSentinel

**Plugin:** `windows.procsentinel`  

A Volatility 3 plugin that:
- Scans running Windows processes for memory‑based anomalies (hollow/process injection, suspicious RWX regions, etc.)  
- Detects singleton‑process anomalies (e.g. duplicate `csrss.exe`, `lsass.exe`, etc.)  
- Dumps and reports any suspicious regions

---

## Installation

1. Copy `procsentinel.py` into your Volatility3 plugins folder:
   ```bash
   cp procsentinel.py ~/volatility3/volatility3/plugins/windows/
   
2. (Re)build any caches if needed:
   ```bash
   vol.py --clear-cache
   
## Usage
```bash
vol.py -f <MEMORY_IMAGE> windows.procsentinel [OPTIONS]

## Common Options
```bash
Flag | Description
--pid <PID1,PID2,…> | Only scan processes with these PIDs
--dump-dir <DIR> | Directory to write dumped memory pages
--yara-output | Generate YARA rules for dumped regions
--check-virustotal | Query VirusTotal for each dump’s SHA256
--csv-report <FILE> | Write findings as CSV
--json-report <FILE> | Write findings as JSON
--html-report <FILE> | Write findings as an HTML report
-vvvvv --log <FILE> | (Core Volatility) Full debug log to <FILE>

vol.py \
  -f ~/dumps/windows11.vmem \
  windows.procsentinel \
    --dump-dir ~/dumps/ps_sentinel \
    --yara-output \
    --check-virustotal \
    --csv-report ~/out/ps_sentinel.csv \
    --json-report ~/out/ps_sentinel.json \
    --html-report ~/out/ps_sentinel.html \
    -vvvvv --log ~/out/ps_sentinel.log

## This will:
```bash
Scan all processes for memory anomalies.

Check for singleton‑process duplicates (e.g. multiple lsass.exe).

Dump suspect pages into ~/dumps/ps_sentinel/.

Emit YARA rules and VT results.

Produce CSV, JSON, and HTML summaries.
