import logging
import os
import hashlib
import csv
import json
from typing import Iterable, Callable, Optional, Tuple

from volatility3.framework import (
    interfaces,
    renderers,
    exceptions,
    constants,
    layers,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import kdbg, pe
from volatility3.framework.objects import utility
from volatility3.plugins.windows import info, pslist, vadinfo, poolscanner
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces.renderers import Disassembly
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from jinja2 import Template

try:
    import requests
except ImportError:
    requests = None

vollog = logging.getLogger(__name__)

HOLLOW_TYPES = [
    "Memory Protection Mismatch",
    "No VAD Entry",
    "Base Address Mismatch",
    "Suspicious Injection"
]

def simple_disassemble(data, start_offset, is_64bit=True):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64bit else CS_MODE_32)
    for insn in md.disasm(data, start_offset):
        yield f"{insn.mnemonic} {insn.op_str}"

class hollowfind(interfaces.plugins.PluginInterface):
    """
    Detects process hollowing and code injection with disassembly, memory dumping,
    command-line keyword filtering, IOC (hash) generation, YARA rule output,
    threat intelligence lookup, and HTML summary reporting.
    Plus CSV/JSON export.
    """
    _required_framework_version = (2, 3, 1)
    _version = (4, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed processes",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Display physical offset instead of virtual",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="dump_dir", description="Directory to dump suspicious memory", optional=True
            ),
            requirements.StringRequirement(
                name="cmd_filter",
                description="Keyword to match in command line for filtering",
                optional=True,
            ),
            requirements.StringRequirement(
                name="html_report", description="Path to write HTML summary report", optional=True
            ),
            requirements.BooleanRequirement(
                name="yara_output",
                description="Output YARA rule for dumped regions",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="check_virustotal",
                description="Check hash on VirusTotal (requires API key env var)",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="aggressive",
                description="Enable aggressive scanning mode",
                optional=True,
                default=False,
            ),
            # NEW: CSV and JSON output options
            requirements.StringRequirement(
                name="csv_report",
                description="Path to write CSV report",
                optional=True,
            ),
            requirements.StringRequirement(
                name="json_report",
                description="Path to write JSON report",
                optional=True,
            ),
        ]

    @classmethod
    def get_osversion(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Tuple[int, int, int]:
        """Returns the complete OS version (MAJ,MIN,BUILD)"""
        kuser = info.Info.get_kuser_structure(
            context, layer_name, symbol_table)
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        vers = info.Info.get_version_structure(
            context, layer_name, symbol_table)
        build = vers.MinorVersion
        return (nt_major_version, nt_minor_version, build)

    def _get_peb_info(self, proc):
        try:
            peb = proc.Peb
            if peb is None:
                return None
            proc_params = peb.ProcessParameters
            cmdline = utility.array_to_string(proc_params.CommandLine.Buffer)
            base_addr = peb.ImageBaseAddress
            return (cmdline, base_addr)
        except exceptions.InvalidAddressException:
            return None

    def _detect_pe_header(self, context, layer_name, start):
        try:
            data = context.layers[layer_name].read(start, 2, pad=True)
            if data == b"MZ":
                return True
        except exceptions.InvalidAddressException:
            pass
        return False

    def _detect_hollowing_or_injection(self, proc):
        """
        Precisely mimic windows.hollowprocesses:
        1) Check main EXE's VAD for unexpected protection
        2) Check each loaded DLL's VAD for unexpected protection
        Normal is PAGE_EXECUTE_WRITECOPY. If not that, we add a finding.
        """
        findings = []
        try:
            kernel = self.context.modules[self.config["kernel"]]
            protect_values = vadinfo.VadInfo.protect_values(
                self.context, kernel.layer_name, kernel.symbol_table_name
            )

            vad_root = proc.get_vad_root()
            if not vad_root:
                return findings

            exe_base = proc.SectionBaseAddress
            peb = proc.Peb
            if (not exe_base or exe_base == 0) and peb:
                if peb.ImageBaseAddress:
                    exe_base = peb.ImageBaseAddress

            exe_vad = None
            if exe_base and exe_base != 0:
                for vad in vad_root.traverse():
                    try:
                        start = vad.get_start()
                        end = vad.get_end()
                        if start <= exe_base < end:
                            exe_vad = vad
                            break
                    except exceptions.InvalidAddressException:
                        continue

                if exe_vad:
                    prot = exe_vad.get_protection(protect_values, vadinfo.winnt_protections)
                    if prot != "PAGE_EXECUTE_WRITECOPY":
                        # show the process name in the message
                        proc_name = utility.array_to_string(proc.ImageFileName)
                        findings.append((f"[{proc_name}] EXE => Unexpected protection ({prot})", exe_vad))

            # now the DLL modules
            if peb and peb.Ldr:
                for module in peb.Ldr.InLoadOrderModuleList:
                    try:
                        dll_base = module.DllBase
                        if not dll_base or dll_base == 0:
                            continue
                        dll_vad = None
                        for vad in vad_root.traverse():
                            try:
                                start = vad.get_start()
                                end = vad.get_end()
                                if start <= dll_base < end:
                                    dll_vad = vad
                                    break
                            except exceptions.InvalidAddressException:
                                continue
                        if dll_vad:
                            prot = dll_vad.get_protection(protect_values, vadinfo.winnt_protections)
                            if prot != "PAGE_EXECUTE_WRITECOPY":
                                proc_name = utility.array_to_string(proc.ImageFileName)
                                findings.append((f"[{proc_name}] DLL => Unexpected protection ({prot})", dll_vad))

                    except exceptions.InvalidAddressException:
                        continue
        except exceptions.InvalidAddressException:
            pass

        return findings

    def _dump_and_disassemble(self, context, proc, vad):
        try:
            task_layer = proc.add_process_layer()
            ep_offset = vad.get_start()
            data = context.layers[task_layer].read(ep_offset, 64, pad=True)
            module = self.context.modules[self.config["kernel"]]
            is_64bit = module.symbol_table_name.startswith("windows")
            disasm = list(simple_disassemble(data, ep_offset, is_64bit))
            return ep_offset, data, disasm
        except exceptions.InvalidAddressException:
            return 0, None, []

    def _dump_memory(self, context, proc, vad_start, pid):
        try:
            dump_dir = self.config.get("dump_dir")
            if dump_dir:
                # Make sure dump_dir exists:
                os.makedirs(dump_dir, exist_ok=True)
                file_path = os.path.join(dump_dir, f"process.{pid}.{vad_start:#x}.dmp")
                task_layer = proc.add_process_layer()
                data = context.layers[task_layer].read(vad_start, 0x1000, pad=True)
                with open(file_path, "wb") as f:
                    f.write(data)
                return file_path, hashlib.sha256(data).hexdigest(), data
        except Exception as e:
            vollog.error(f"Failed to dump memory for PID {pid}: {e}")
        return None, None, None

    def _generate_yara_rule(self, data, sha256_hash):
        hex_string = " ".join(f"{b:02x}" for b in data[:16])
        return f"""
rule hollowfind_{sha256_hash[:8]} {{
    strings:
        $code = {{ {hex_string} }}
    condition:
        $code
}}
"""

    def _write_yara_batch(self, rows, output_path="yara_rules.yar"):
        if not rows:
            return
        try:
            with open(output_path, "w") as f:
                for r in rows:
                    rule = r[15]  # YARA Rule
                    if rule:
                        f.write(rule + "\n")
        except Exception as e:
            vollog.warning(f"Failed to write YARA batch file: {e}")

    def _query_virustotal(self, sha256_hash):
        if not requests:
            return "requests module missing"
        apikey = os.getenv("VT_API_KEY")
        if not apikey:
            return "VT_API_KEY not set"
        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            headers = {"x-apikey": apikey}
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                score = data["data"]["attributes"]["last_analysis_stats"]
                return f"Detected by {score['malicious']} engines"
            return f"Error {resp.status_code}"
        except Exception as e:
            return str(e)

    def _generate_html_report(self, rows, path):
        template = Template(
            """
        <html><head><title>HollowFind Report</title></head><body>
        <h2>Suspicious Processes</h2>
        <table border="1">
        <tr><th>PID</th><th>Name</th><th>PPID</th><th>Type</th><th>Hash</th><th>MITRE Tactic</th><th>YARA</th><th>VT Result</th></tr>
        {% for r in rows %}
        <tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3]}}</td><td>{{r[14]}}</td><td>{{r[17]}}</td><td><pre>{{r[15]}}</pre></td><td>{{r[16]}}</td></tr>
        {% endfor %}
        </table></body></html>
        """
        )
        with open(path, "w") as f:
            f.write(template.render(rows=rows))

    # optional CSV
    def _write_csv_report(self, rows, csv_path):
        headers = [
            "PID",
            "Process Name",
            "Parent PID",
            "Hollow Type",
            "Command Line (PEB)",
            "Base Address (PEB)",
            "VAD Filename",
            "VAD Base Address",
            "VAD Size",
            "VAD Protection",
            "VAD Tag",
            "Disassembly",
            "Hex Dump",
            "Dump Path",
            "SHA256 Hash",
            "YARA Rule",
            "VirusTotal Result",
            "MITRE ATT&CK",
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)

    # optional JSON
    def _write_json_report(self, rows, json_path):
        final = []
        for row in rows:
            # row is a tuple of 18 items
            final.append({
                "PID": row[0],
                "Process Name": row[1],
                "Parent PID": row[2],
                "Hollow Type": row[3],
                "Command Line (PEB)": row[4],
                "Base Address (PEB)": str(row[5]),
                "VAD Filename": row[6],
                "VAD Base Address": str(row[7]),
                "VAD Size": str(row[8]),
                "VAD Protection": row[9],
                "VAD Tag": row[10],
                "Disassembly": row[11],
                "Hex Dump": row[12],
                "Dump Path": row[13],
                "SHA256 Hash": row[14],
                "YARA Rule": row[15],
                "VirusTotal Result": row[16],
                "MITRE ATT&CK": row[17],
            })
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(final, f, indent=2)

    def _map_to_mitre(self, hollow_type):
        tactic_map = {
            0: "Defense Evasion - T1055",
            1: "Defense Evasion - T1027",
            2: "Defense Evasion - T1055.012",
            3: "Defense Evasion - T1055 (Generic Injection)",
        }
        return tactic_map.get(hollow_type, "Unknown")

    def _generator(self, results):
        for entry in results:
            yield (0, entry)

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        filter_pids = self.config.get("pid", None)
        cmd_filter = self.config.get("cmd_filter", None)
        html_path = self.config.get("html_report", None)
        do_yara = self.config.get("yara_output", False)
        do_vt = self.config.get("check_virustotal", False)

        csv_path = self.config.get("csv_report", None)
        json_path = self.config.get("json_report", None)

        proc_list = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        )

        results = []

        for proc in proc_list:
            pid = proc.UniqueProcessId
            if filter_pids and pid not in filter_pids:
                continue

            name = utility.array_to_string(proc.ImageFileName)
            ppid = proc.InheritedFromUniqueProcessId
            peb_info = self._get_peb_info(proc)

            if cmd_filter and (
                not peb_info or cmd_filter.lower() not in peb_info[0].lower()
            ):
                continue

            # detection function
            hollow_findings = self._detect_hollowing_or_injection(proc)

            for (finding_msg, suspicious_vad) in hollow_findings:
                ep_offset, disasm_data, disasm = self._dump_and_disassemble(
                    self.context, proc, suspicious_vad
                )
                dumped_path, sha256_hash, raw_data = self._dump_memory(
                    self.context, proc, suspicious_vad.get_start(), pid
                )

                yara_rule = ""
                if do_yara and raw_data:
                    yara_rule = self._generate_yara_rule(raw_data, sha256_hash)

                vt_status = ""
                if do_vt and sha256_hash:
                    vt_status = self._query_virustotal(sha256_hash)

                mitre = self._map_to_mitre(0)

                hex_lines = []
                if disasm_data:
                    for i in range(0, len(disasm_data), 16):
                        chunk = disasm_data[i : i+16]
                        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                        hex_lines.append(f"{ep_offset + i:08x}  {hex_bytes:<48}  {ascii_str}")

                prot = suspicious_vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context,
                        kernel.layer_name,
                        kernel.symbol_table_name,
                    ),
                    vadinfo.winnt_protections,
                ) or ""

                raw_file_obj = suspicious_vad.get_file_name()
                if not raw_file_obj or isinstance(raw_file_obj, renderers.NotApplicableValue):
                    file_name = "<Non-File Backed Region>"
                else:
                    file_name = str(raw_file_obj)

                tag = suspicious_vad.get_tag() or ""

                results.append(
                    (
                        pid,
                        name,
                        ppid,
                        finding_msg,
                        peb_info[0] if peb_info else "",
                        format_hints.Hex(peb_info[1]) if peb_info else format_hints.Hex(0),
                        file_name,
                        format_hints.Hex(suspicious_vad.get_start()),
                        format_hints.Hex(suspicious_vad.get_end() - suspicious_vad.get_start()),
                        prot,
                        tag,
                        "\n".join(disasm),
                        "\n".join(hex_lines),
                        dumped_path or "",
                        sha256_hash or "",
                        yara_rule.strip(),
                        vt_status.strip(),
                        mitre,
                    )
                )

        # generate all reports if needed
        if html_path:
            self._generate_html_report(results, html_path)
        if csv_path:
            self._write_csv_report(results, csv_path)
        if json_path:
            self._write_json_report(results, json_path)
        if do_yara:
            self._write_yara_batch(results)

        # final render
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process Name", str),
                ("Parent PID", int),
                ("Hollow Type", str),
                ("Command Line (PEB)", str),
                ("Base Address (PEB)", format_hints.Hex),
                ("VAD Filename", str),
                ("VAD Base Address", format_hints.Hex),
                ("VAD Size", format_hints.Hex),
                ("VAD Protection", str),
                ("VAD Tag", str),
                ("Disassembly", str),
                ("Hex Dump", str),
                ("Dump Path", str),
                ("SHA256 Hash", str),
                ("YARA Rule", str),
                ("VirusTotal Result", str),
                ("MITRE ATT&CK", str),
            ],
            ((0, r) for r in results),
        )
