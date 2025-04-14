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



SAMPLE Output 1:

rootx@DFIRBoxWSL:~$ python3 ~/volatility3-2.11.0/vol.py --clear-cache -f /mnt/c/Users/user/Desktop/stuxnet.vmem windows.hollowfind --dump-dir /mnt/c/Users/user/Desktop/dumps --yara-output --check-virustotal --csv-report /mnt/c/Users/user/Desktop/out.csv --json-report /mnt/c/Users/user/Desktop/out.json --html-report /mnt/c/Users/user/Desktop/out.html

Volatility 3 Framework 2.11.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. stuxnet.vmem and stuxnet.vmss.
Progress:  100.00               PDB scanning finished
PID     Process Name    Parent PID      Hollow Type     Command Line (PEB)      Base Address (PEB)      VAD Filename    VAD Base Address        VAD Size    VAD Protection   VAD Tag Disassembly     Hex Dump        Dump Path       SHA256 Hash     YARA Rule       VirusTotal Result       MITRE ATT&CK

868     lsass.exe       668     [lsass.exe] EXE => Unexpected protection (PAGE_EXECUTE_READWRITE)               0x0     <Non-File Backed Region>        0x1000000    0x5fff  PAGE_EXECUTE_READWRITE  Vad     dec ebp
pop edx
nop
add byte ptr [ebx], al
add byte ptr [eax], al
add byte ptr [eax + eax], al
add byte ptr [eax], al  01000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
01000010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
01000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
01000030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................    /mnt/c/Users/bedan/Desktop/dumps/process.868.0x1000000.dmp      68269b89dd69967adbd8891e3f3eeea42c11b1278bc7fb1735c420b677010760     rule hollowfind_68269b89 {
    strings:
        $code = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        $code
}       Error 404       Defense Evasion - T1055
1928    lsass.exe       668     [lsass.exe] EXE => Unexpected protection (PAGE_EXECUTE_READWRITE)               0x0     <Non-File Backed Region>        0x1000000    0x5fff  PAGE_EXECUTE_READWRITE  Vad     dec ebp
pop edx
nop
add byte ptr [ebx], al
add byte ptr [eax], al
add byte ptr [eax + eax], al
add byte ptr [eax], al  01000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
01000010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
01000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
01000030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................    /mnt/c/Users/bedan/Desktop/dumps/process.1928.0x1000000.dmp     68269b89dd69967adbd8891e3f3eeea42c11b1278bc7fb1735c420b677010760     rule hollowfind_68269b89 {
    strings:
        $code = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        $code
}       Error 404       Defense Evasion - T1055


SAMPLE Output 2:

Volatility 3 Framework 2.11.0
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. stuxnet.vmem and stuxnet.vmss.
Progress:  100.00               PDB scanning finished
PID     Process Name    Parent PID      Hollow Type     Command Line (PEB)      Base Address (PEB)      VAD Filename    VAD Base Address        VAD Size    VAD Protection   VAD Tag Disassembly     Hex Dump        Dump Path       SHA256 Hash     YARA Rule       VirusTotal Result       MITRE ATT&CK

868     lsass.exe       668     [lsass.exe] EXE => Unexpected protection (PAGE_EXECUTE_READWRITE)               0x0     <Non-File Backed Region>        0x1000000    0x5fff  PAGE_EXECUTE_READWRITE  Vad     dec ebp
pop edx
nop
add byte ptr [ebx], al
add byte ptr [eax], al
add byte ptr [eax + eax], al
add byte ptr [eax], al  01000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
01000010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
01000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
01000030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................    /mnt/c/Users/bedan/Desktop/dumps/process.868.0x1000000.dmp      68269b89dd69967adbd8891e3f3eeea42c11b1278bc7fb1735c420b677010760     rule hollowfind_68269b89 {
    strings:
        $code = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        $code
}       Error 404       Defense Evasion - T1055
1928    lsass.exe       668     [lsass.exe] EXE => Unexpected protection (PAGE_EXECUTE_READWRITE)               0x0     <Non-File Backed Region>        0x1000000    0x5fff  PAGE_EXECUTE_READWRITE  Vad     dec ebp
pop edx
nop
add byte ptr [ebx], al
add byte ptr [eax], al
add byte ptr [eax + eax], al
add byte ptr [eax], al  01000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
01000010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
01000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
01000030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................    /mnt/c/Users/bedan/Desktop/dumps/process.1928.0x1000000.dmp     68269b89dd69967adbd8891e3f3eeea42c11b1278bc7fb1735c420b677010760     rule hollowfind_68269b89 {
    strings:
        $code = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        $code
}       Error 404       Defense Evasion - T1055
rootx@DFIRBoxWSL:~$ python3 ~/volatility3-2.11.0/vol.py --clear-cache -f /mnt/c/Users/bedan/Desktop/hollow1.dmp windows.hollowfind --dump-dir /mnt/c/Users/be
dan/Desktop/dumps --yara-output --check-virustotal --csv-report /mnt/c/Users/bedan/Desktop/out.csv --json-report /mnt/c/Users/bedan/Desktop/out.json --html-r
eport /mnt/c/Users/bedan/Desktop/out.html
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
PID     Process Name    Parent PID      Hollow Type     Command Line (PEB)      Base Address (PEB)      VAD Filename    VAD Base Address        VAD Size    VAD Protection   VAD Tag Disassembly     Hex Dump        Dump Path       SHA256 Hash     YARA Rule       VirusTotal Result       MITRE ATT&CK

11712   lsass.exe       7772    [lsass.exe] EXE => Unexpected protection (PAGE_EXECUTE_READWRITE)               0x0     <Non-File Backed Region>        0x7ff7183e0000       0x4fff  PAGE_EXECUTE_READWRITE  VadS    dec ebp
pop edx
nop
add byte ptr [ebx], al
add byte ptr [eax], al
add byte ptr [eax + eax], al
add byte ptr [eax], al  7ff7183e0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
7ff7183e0010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
7ff7183e0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
7ff7183e0030  00 00 00 00 00 00 00 00 00 00 00 00 c8 00 00 00   ................        /mnt/c/Users/bedan/Desktop/dumps/process.11712.0x7ff7183e0000.dmp   d3a8e573043f3f76f92a25c562531d93b3894abfd943a5dd679a5b412e8bfb41 rule hollowfind_d3a8e573 {
    strings:
        $code = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        $code
}       Detected by 12 engines  Defense Evasion - T1055
