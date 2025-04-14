HollowFind is a Volatility 3 plugin designed to detect process hollowing and code injection artifacts in Windows memory dumps. It closely replicates the logic of Volatility’s windows.hollowprocesses plugin while adding features like:

Memory dumping of suspicious regions

Automatic YARA rule generation from suspicious memory

VirusTotal lookups for the memory’s hash

CSV, JSON, and HTML reporting

**Features**

  Process Hollowing Detection

    Identifies processes whose main EXE or loaded DLLs have mismatched memory protections (expected PAGE_EXECUTE_WRITECOPY, found PAGE_EXECUTE_READWRITE, etc.).

  Suspicious Region Dumping

    Optionally dumps suspicious memory pages for later analysis.

  YARA Rule Generation

    Generates a minimal YARA signature from the memory’s first bytes.

  VirusTotal Lookup

    Checks each suspicious region’s SHA-256 hash against VirusTotal, appending the detection ratio or error.

  Multiple Output Formats

    Human-readable console output

    CSV / JSON / HTML reports for easy external analysis

  Optional aggressive Mode

    Provide an extra check to flag more potential injection scenarios.

**Installation**

  Clone or download Volatility 3 from the official repository: Tested with stable version Volatility 3 2.11.0
  Place this plugin (hollowfind.py) under: volatility3/volatility3/plugins/windows/
  Install any dependencies if missing:

    capstone for disassembly

    requests if you want VirusTotal lookups

    jinja2 if generating HTML

  (Optional) Set VT_API_KEY environment variable if you want to do VirusTotal checks: export VT_API_KEY="Your_VT_key_here"
  
Basic Command: python3 vol.py -f <memory_dump> windows.hollowfind

Advanced Options
Key arguments (as recognized by Volatility from the plugin’s requirements):

--dump-dir <path>
Directory to dump suspicious memory pages into.

--yara-output
Generate a minimal YARA rule for each dumped region.

--check-virustotal
Query VirusTotal for each region’s SHA-256 hash (requires VT_API_KEY).

--csv-report <path>
Write results in CSV format.

--json-report <path>
Write results in JSON format.

--html-report <path>
Write results in an HTML table.

--pid <PID>
Only check the specified PID(s).

--cmd-filter <keyword>
Only check processes whose PEB command line contains the keyword.

--aggressive
Enable additional checks (optional).


Report Outputs
When you specify one (or more) of --csv-report, --json-report, or --html-report, HollowFind will write the detection data into that file in the chosen format.

CSV Output
Contains columns for PID, Process Name, Parent PID, Hollow Type, Command Line (PEB), Base Address (PEB), VAD Filename, Dump Path, SHA256 Hash, YARA Rule, VirusTotal Result, and more.

Easy to open in Excel or manipulate with other tools.

JSON Output
Each suspicious region is serialized as a JSON object with keys matching the columns.

Good for programmatic ingestion into other security tools or SIEMs.

HTML Output
Simple table-based layout with the same columns.

Use any browser to quickly review suspicious processes and memory regions.

Dump suspicious memory and generate YARA, VirusTotal, CSV, JSON, and HTML:

export VT_API_KEY="123456789abcdef"
python3 vol.py \
    -f /path/to/malware.vmem \
    windows.hollowfind \
    --dump-dir /tmp/hollow_dumps \
    --yara-output \
    --check-virustotal \
    --csv-report /tmp/hollow_out.csv \
    --json-report /tmp/hollow_out.json \
    --html-report /tmp/hollow_out.html

Only check a single PID with a command line filter:
python3 vol.py -f stuxnet.vmem windows.hollowfind \
    --pid 11712 \
    --cmd-filter "lsass.exe"
