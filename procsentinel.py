import logging, os, hashlib, csv, json, re
from itertools import chain
from typing import Iterable, Callable, Optional, Tuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from jinja2 import Template
import volatility3.framework.renderers.format_hints as format_hints
from volatility3.cli.text_renderer import QuickTextRenderer
from volatility3.framework import interfaces, renderers, exceptions, constants, layers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.interfaces.renderers import Disassembly
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import kdbg, pe
from volatility3.framework.objects import utility
from volatility3.framework.renderers import NotApplicableValue
from volatility3.plugins.windows import info, pslist, vadinfo, poolscanner

try:
    import requests
except ImportError:
    requests = None

vollog = logging.getLogger("volatility3.plugins.windows.procsentinel")

QuickTextRenderer._type_renderers[format_hints.Hex] = QuickTextRenderer._type_renderers["default"]

class BannerHex(format_hints.Hex):
    def __new__(cls, value, banner=None):
        # If value isn’t a real number (e.g. a stray type), fall back to 0
        try:
            inst = super().__new__(cls, value)
        except TypeError:
            inst = super().__new__(cls, 0)
        # Store either the override banner or the plain hex digits
        inst.banner = banner if banner is not None else int.__format__(inst, "x")
        return inst

    def __str__(self):
        return self.banner

    __repr__ = __str__

    def __format__(self, spec):
        # Ignore any format specifier (':x', '#x', etc.)
        return self.banner
format_hints.Hex = BannerHex

class BannerInt(int):
    def __new__(cls, value, banner=None):
        inst = super().__new__(cls, value)
        inst.banner = banner if banner is not None else str(inst)
        return inst

    def __str__(self):
        return self.banner

    __repr__ = __str__

    def __format__(self, spec):
        return self.banner

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


class ProcSentinel(interfaces.plugins.PluginInterface):
  
    _required_framework_version = (
        constants.VERSION_MAJOR, 
        constants.VERSION_MINOR
    )
    _version = (1, 0, 0)
    
    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist",
                plugin=pslist.PsList,
                version=pslist.PsList._version
            ),
            requirements.PluginRequirement(
                name="info",
                plugin=info.Info,
                version=info.Info._version
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
    
    def _scan_all_execute_vads(self, proc):
        findings = []
        try:
            vad_root = proc.get_vad_root()
            if not vad_root:
                return findings

            kernel = self.context.modules[self.config["kernel"]]

            protect_values = vadinfo.VadInfo.protect_values(
                self.context, kernel.layer_name, kernel.symbol_table_name
            )

            # Build list of known DLL base addresses
            known_bases = set()
            peb = proc.Peb
            if peb and peb.Ldr:
                for module in peb.Ldr.InLoadOrderModuleList:
                    try:
                        dll_base = module.DllBase
                        if dll_base:
                            known_bases.add(dll_base)
                    except exceptions.InvalidAddressException:
                        continue

            for vad in vad_root.traverse():
                try:
                    start = vad.get_start()
                    end = vad.get_end()
                    protection = vad.get_protection(protect_values, vadinfo.winnt_protections)

                    # Focus on RWX memory regions
                    if protection == "PAGE_EXECUTE_READWRITE":
                        # Skip VADs corresponding to known DLLs
                        if start in known_bases:
                            continue

                        # Check first two bytes for MZ header
                        task_layer = proc.add_process_layer()
                        data = self.context.layers[task_layer].read(start, 2, pad=True)
                        if data == b"MZ":
                            findings.append(("Suspicious RWX VAD with MZ header", vad))
                except exceptions.InvalidAddressException:
                    continue

        except exceptions.InvalidAddressException:
            pass

        return findings

    def _scan_blind_rwx_mz_vads(self, proc):
        findings = []
        try:
            vad_root = proc.get_vad_root()
            if not vad_root:
                return findings

            for vad in vad_root.traverse():
                kernel = self.context.modules[self.config["kernel"]]
                prot = vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context,
                        kernel.layer_name,
                        kernel.symbol_table_name,
                    ),
                    vadinfo.winnt_protections,
                )
                if prot == "PAGE_EXECUTE_READWRITE":
                    # Read first 2 bytes
                    try:
                        task_layer = proc.add_process_layer()
                        data = self.context.layers[task_layer].read(vad.get_start(), 2, pad=True)
                        if data == b"MZ":
                            findings.append((
                                "[Blind] RWX Region with MZ header",
                                vad
                            ))
                    except exceptions.InvalidAddressException:
                        continue
        except exceptions.InvalidAddressException:
            pass

        return findings
    
    def _detect_behavior_anomalies(self, proc_list):
        
        # ------------------------------------------------------------------
        # 0.  Imports / helpers
        # ------------------------------------------------------------------
        import os, logging, hashlib
        from typing import List, Tuple

        from volatility3.framework import exceptions, interfaces, renderers
        from volatility3.framework.objects import utility
        from volatility3.framework.renderers import format_hints

        vollog = logging.getLogger(__name__)

        dump_dir: str | None = self.config.get("dump_dir", None)
        if dump_dir:
            try:
                os.makedirs(dump_dir, exist_ok=True)
            except Exception as e:
                vollog.warning(f"Could not create dump‑dir '{dump_dir}': {e} – disabling dumps")
                dump_dir = None

        # ------------------------------------------------------------------
        # 1.  Static data / expectations
        # ------------------------------------------------------------------
        singleton_processes = {
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "lsass.exe", "explorer.exe", "taskhostw.exe", "dwm.exe", "spoolsv.exe",
            "userinit.exe", "logonui.exe", "audiodg.exe",
        }

        expected_location_svchost   = r"c:\\windows\\system32"
        expected_taskhostw_path     = r"c:\\windows\\system32\\taskhostw.exe"
        expected_parent_svchost     = "services.exe"
        expected_cmd_keywords       = ["-k"]
        expected_usernames_svchost  = {"system", "local service", "network service"}

        # ------------------------------------------------------------------
        # 2.  Working containers
        # ------------------------------------------------------------------
        anomalies: List[Tuple] = []
        svchost_anomalies: List[Tuple] = []

        singleton_entries: dict[str, list] = {}
        taskhostw_valid:   dict[int, bool] = {}
        pid_map = {int(p.UniqueProcessId): p for p in proc_list}

        # ------------------------------------------------------------------
        # 3.  Walk every process once
        # ------------------------------------------------------------------
        for proc in proc_list:
            pid  = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)

            try:
                name = utility.array_to_string(proc.ImageFileName).strip("\x00\0").lower()
            except exceptions.InvalidAddressException:
                vollog.debug(f"[detect‑anomaly] ImageFileName fault for PID {pid}")
                continue

            if name in ("system", "registry", "memcompression", ""):
                continue
            
            if name in singleton_processes:
                singleton_entries.setdefault(name, []).append([pid, ppid, "<pending path>"])
            
            proc_path, cmdline = "<missing>", "<missing>"
            try:
                peb = proc.Peb
            except exceptions.InvalidAddressException:
                peb = None

            if peb:
                try:
                    pp = peb.ProcessParameters
                except exceptions.InvalidAddressException:
                    pp = None
                if pp:
                    try:
                        proc_path = pp.ImagePathName.get_string().lower()
                        cmdline   = pp.CommandLine.get_string().lower()
                    except exceptions.InvalidAddressException:
                        proc_path = cmdline = "<unreadable>"

            if proc_path in ("<missing>", "<unreadable>"):
                try:
                    alt = proc.get_process_path()
                    if alt:
                        proc_path = alt.lower()
                except Exception:
                    pass

            if name in singleton_processes:
                singleton_entries[name][-1][2] = proc_path or "<missing>"

                vollog.debug(
                    "[detect‑anomaly] "
                    f"PID {pid:>5}  "
                    f"{name:<15}  "
                    f"path={proc_path or '<na>':<50}  "
                    f"cmd={cmdline or '<na>'}"
                )

            # ----------------------------- svchost deep‑dive ------------------------------------
            if name == "svchost.exe":
                reasons: list[str] = []
                if proc_path not in ("<missing>", "<unreadable>") and expected_location_svchost not in proc_path:
                    reasons.append("runs from unexpected location")
                if cmdline not in ("<missing>", "<unreadable>") and not any(k in cmdline for k in expected_cmd_keywords):
                    reasons.append("missing or unusual command line")
                try:
                    username = "".join(proc.Token.get_account_name()).lower()
                    if username and username not in expected_usernames_svchost:
                        reasons.append(f"unexpected username ({username})")
                except Exception:
                    vollog.debug(f"[svchost] token read failed PID {pid}")
                try:
                    if not list(proc.get_loadable_services()):
                        reasons.append("no hosted services found")
                except Exception:
                    vollog.debug(f"[svchost] service enum failed PID {pid}")
                parent_proc = pid_map.get(ppid)
                if not parent_proc:
                    reasons.append("parent process missing")
                else:
                    try:
                        parent_name = utility.array_to_string(parent_proc.ImageFileName).lower()
                        if expected_parent_svchost not in parent_name:
                            reasons.append("unexpected parent process")
                    except exceptions.InvalidAddressException:
                        reasons.append("parent name unreadable")
                try:
                    signed, publisher = proc.check_signature()
                    if not signed or "microsoft" not in publisher.lower():
                        reasons.append("not signed by Microsoft")
                except Exception:
                    vollog.debug(f"[svchost] signature check failed PID {pid}")

                if len(reasons) >= 2:
                    svchost_anomalies.append((
                        pid, name, ppid,
                        "SUSPICIOUS->INVESTIGATE (svchost irregularities: " + ", ".join(reasons) + ")",
                        "", format_hints.Hex(0), proc_path, format_hints.Hex(0),
                        format_hints.Hex(0), "", "", "", "", "", "", "", "", "Masquerading - T1036"
                    ))

            # -------------------------------taskhostw validation ---------------------------------
            if name == "taskhostw.exe":
                valid = True
                if expected_taskhostw_path not in proc_path:
                    valid = False
                try:
                    signed, publisher = proc.check_signature()
                    if not signed or "microsoft" not in publisher.lower():
                        valid = False
                except Exception:
                    valid = False
                taskhostw_valid[pid] = valid
                vollog.debug(f"[taskhostw] PID {pid} valid → {valid}")

        # ------------------------------------------------------------------
        # 4.  Singleton evaluation with PID‑ranking
        # ------------------------------------------------------------------
        for name, entries in singleton_entries.items():
            # csrss.exe: up to 2 instances are expected
            if name == "csrss.exe" and len(entries) <= 2:
                continue
            # taskhostw carve‑out: ≤2 copies with identical parent process
            if name == "taskhostw.exe":
                if len(entries) <= 2 and len({ppid for _, ppid, _ in entries}) == 1:
                    continue
            if len(entries) > 1:
                entries_sorted = sorted(entries, key=lambda x: x[0])
                authentic_pid = entries_sorted[0][0]
                for pid, ppid, path in entries_sorted:
                    if pid == authentic_pid:
                        desc = "Authentic Process (lowest PID in duplicate set)"
                    else:
                        desc = "SUSPICIOUS->INVESTIGATE (Multiple Instances of Singleton Process)"
                    anomalies.append((
                        pid, name, ppid, desc,
                        "", format_hints.Hex(0), path, format_hints.Hex(0),
                        format_hints.Hex(0), "", "", "", "", "", "", "", "", "Masquerading - T1036"
                    ))

        total_findings = anomalies + svchost_anomalies


        vollog.debug(f"[detect‑anomaly] total anomalies → {len(total_findings)}")

        # ------------------------------------------------------------------
        # 6.  Return findings – TreeGrid renderer prints headers
        # ------------------------------------------------------------------
        return total_findings


    def _detect_hollowing_or_injection(self, proc):
        
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
                    prot = exe_vad.get_protection(
                        protect_values, vadinfo.winnt_protections)
                    if prot != "PAGE_EXECUTE_WRITECOPY":
                        proc_name = utility.array_to_string(proc.ImageFileName)
                        findings.append(
                            (f"[{proc_name}] EXE => Unexpected protection ({prot})", exe_vad))
                                            

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
                            prot = dll_vad.get_protection(
                                protect_values, vadinfo.winnt_protections)
                            if prot != "PAGE_EXECUTE_WRITECOPY":
                                proc_name = utility.array_to_string(
                                    proc.ImageFileName)
                                findings.append(
                                    (f"[{proc_name}] DLL => Unexpected protection ({prot})", dll_vad))

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
                os.makedirs(dump_dir, exist_ok=True)
                file_path = os.path.join(
                    dump_dir, f"process.{pid}.{vad_start:#x}.dmp")
                task_layer = proc.add_process_layer()
                data = context.layers[task_layer].read(
                    vad_start, 0x1000, pad=True)
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
                    rule = r[15]
                    if rule:
                        f.write(rule + "\n")
        except Exception as e:
            vollog.warning(f"Failed to write YARA batch file: {e}")

    def _query_virustotal(self, sha256_hash):
        if not requests:
            return "requests module missing"
        apikey = os.getenv("VT_API_KEY")
        if not apikey:
            return "VT_API_KEY is NOT set as Environment Variable"
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

    def _generate_html_report(self, rows, html_path):
        template = Template(
            """
        <html><head><title>HollowFind Report</title></head><body>
        <h2>Suspicious Processes</h2>
        <table border="1">
          <tr>
            <th>PID</th>
            <th>Name</th>
            <th>PPID</th>
            <th>Type</th>
            <th>VAD Filename</th>
            <th>VAD Protection</th>
            <th>Dump Path</th>
            <th>Hash</th>
            <th>MITRE Tactic</th>
            <th>YARA</th>
            <th>VT Result</th>
          </tr>
        {% for r in rows %}
          <tr>
            <td>{{ r[0] }}</td>
            <td>{{ r[1] }}</td>
            <td>{{ r[2] }}</td>
            <td>{{ r[3] }}</td>
            <td>{{ r[6]|e }}</td>
            <td>{{ r[9] }}</td>
            <td>{{ r[13] }}</td>
            <td>{{ r[14] }}</td>
            <td>{{ r[17] }}</td>
            <td><pre>{{ r[15] }}</pre></td>
            <td>{{ r[16] }}</td>
          </tr>
        {% endfor %}
        </table></body></html>
        """
        )
        with open(html_path, "w") as f:
            f.write(template.render(rows=rows))
    
    def _generate_csv_report(self, rows, csv_path):
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
    
    def _generate_json_report(self, rows, json_path):
        def _clean(val):
           
            if val is None or isinstance(val, (str, int, float, bool)):
                return val
            if isinstance(val, renderers.NotApplicableValue):
                return None
            if isinstance(val, format_hints.MultiTypeData):
                return str(val)
            return str(val)
        out = []
        for row in rows:
            out.append({
                "PID":                     _clean(row[0]),
                "Process Name":            _clean(row[1]),
                "Parent PID":              _clean(row[2]),
                "Hollow Type":             _clean(row[3]),
                "Command Line (PEB)":      _clean(row[4]),
                "Base Address (PEB)":      _clean(row[5]),
                "VAD Filename":            _clean(row[6]),
                "VAD Base Address":        _clean(row[7]),
                "VAD Size":                _clean(row[8]),
                "VAD Protection":          _clean(row[9]),
                "VAD Tag":                 _clean(row[10]),
                "Disassembly":             _clean(row[11]),
                "Hex Dump":                _clean(row[12]),
                "Dump Path":               _clean(row[13]),
                "SHA256 Hash":             _clean(row[14]),
                "YARA Rule":               _clean(row[15]),
                "VirusTotal Result":       _clean(row[16]),
                "MITRE ATT&CK":            _clean(row[17]),
            })

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)

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
        cmd_filter = (self.config.get("cmd_filter") or "").lower()
        html_path = self.config.get("html_report", None)
        csv_path = self.config.get("csv_report", None)
        json_path = self.config.get("json_report", None)
        do_yara = self.config.get("yara_output", False)
        do_vt = self.config.get("check_virustotal", False)
        dump_dir = self.config.get("dump_dir", None)

        columns = [
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
        ]
        
        try:
            # Newer Volatility3: list_processes(context, kernel_module_name, filter_func=…)
            proc_list = list(pslist.PsList.list_processes(
                self.context,
                self.config["kernel"]
            ))
        except TypeError:
            # Older Volatility3: list_processes(context, layer_name, symbol_table)
            proc_list = list(pslist.PsList.list_processes(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name
            ))        

        anomaly_findings = self._detect_behavior_anomalies(proc_list)
        vollog.debug(f"[hollowfind] Behavior anomalies detected: {len(anomaly_findings)}")
         
        results = []
        vollog.debug(f"[hollowfind] Total processes: {len(proc_list)}")

        for proc in proc_list:
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            if filter_pids and pid not in filter_pids:
                    continue

            name = utility.array_to_string(proc.ImageFileName)
            ppid = proc.InheritedFromUniqueProcessId
            peb_info = self._get_peb_info(proc)

            if cmd_filter and (
                    not peb_info or cmd_filter.lower() not in peb_info[0].lower()
            ):
                    continue

            hollow_findings = self._detect_hollowing_or_injection(proc)
            extra_findings = self._scan_all_execute_vads(proc)
            extra_blind_findings = self._scan_blind_rwx_mz_vads(proc)
            combined_findings = hollow_findings + extra_findings + extra_blind_findings
            dumped_addresses: dict[int, str] = {}
            for finding_msg, suspicious_vad in combined_findings:
                vad_start = suspicious_vad.get_start()

                # 1) only dump once per unique VAD
                if vad_start not in dumped_addresses:
                    # perform the dump
                    dumped, sha256, raw = self._dump_memory(
                        self.context, proc, vad_start, pid
                    )

                    if dump_dir and dumped:
                        # name it "Malicious_{proc}_{addr}_Image.dmp"
                        new_name = f"Malicious_{name}_{vad_start:08x}_Image.dmp"
                        new_path = os.path.join(dump_dir, new_name)
                        try:
                            os.replace(dumped, new_path)
                        except OSError:
                            os.rename(dumped, new_path)
                        vollog.info(f"Wrote malicious memory page to {new_path}")
                        dumped_addresses[vad_start] = new_path
                    else:
                        # no dump → record empty so we don’t retry
                        dumped_addresses[vad_start] = ""

                # 2) reuse the dump path (or empty string)
                dump_path = dumped_addresses[vad_start]

                # 3) disassemble the same VAD if you need hex/dasm output
                ep_offset, disasm_data, disasm = self._dump_and_disassemble(
                    self.context, proc, suspicious_vad
                )

                # 4) build YARA / VT only once per VAD
                yara_rule = ""
                if do_yara and raw:
                    yara_rule = self._generate_yara_rule(raw, sha256)

                vt_status = ""
                if do_vt and sha256:
                    vt_status = self._query_virustotal(sha256)

                mitre = self._map_to_mitre(0)

                # 5) build your hex‑lines
                hex_lines = []
                if disasm_data:
                    for i in range(0, len(disasm_data), 16):
                        chunk = disasm_data[i : i + 16]
                        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                        hex_lines.append(f"{ep_offset + i:08x}  {hex_bytes:<48}  {ascii_str}")

                # 6) other VAD fields
                prot = suspicious_vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context, kernel.layer_name, kernel.symbol_table_name
                    ),
                    vadinfo.winnt_protections,
                ) or ""

                fn_obj = suspicious_vad.get_file_name()
                file_name = (
                    "<Non-File Backed Region>"
                    if fn_obj is None or isinstance(fn_obj, NotApplicableValue)
                    else str(fn_obj)
                )
                tag = suspicious_vad.get_tag() or ""

                # 7) append the tuple, using our deduped dump_path
                results.append((
                    pid,
                    name,
                    ppid,
                    finding_msg,
                    peb_info[0] if peb_info else "",
                    format_hints.Hex(peb_info[1]) if peb_info else format_hints.Hex(0),
                    file_name,
                    format_hints.Hex(vad_start),
                    format_hints.Hex(suspicious_vad.get_end() - vad_start),
                    prot,
                    tag,
                    "\n".join(disasm),
                    "\n".join(hex_lines),
                    dump_path,
                    sha256 or "",
                    yara_rule.strip(),
                    vt_status.strip(),
                    mitre
                ))
        # build a pid→proc map to re‑fetch the process object
        pid_map = { int(p.UniqueProcessId): p for p in proc_list }
        
        banner_row = []
        for _, col_type in columns:
            if col_type is int:
                banner_row.append(BannerInt(0, "PROCESS‑ANOMALIES"))
            elif col_type is format_hints.Hex:
                banner_row.append(format_hints.Hex(0, "PROCESS‑ANOMALIES"))
            else:
                banner_row.append("PROCESS‑ANOMALIES")
        banner_row = tuple(banner_row)

        if anomaly_findings:
            results.append(banner_row)
          
            for ( pid, name, ppid, desc,
                   cmdline, base, path, start, size,
                   prot, tag, disasm, hexdump,
                   dump_path, sha, yara, vt,
                   mitre_field
                 ) in anomaly_findings:
                if not desc.startswith("SUSPICIOUS->INVESTIGATE (Multiple Instances"):
                    continue

                proc = pid_map.get(pid)
                if not proc:
                    continue

                # --- PEB info ---
                peb_info = self._get_peb_info(proc) or ("", 0)
                cmdline, base_addr = peb_info
                peb_base = format_hints.Hex(base_addr)

                # --- EXE base fallback logic ---
                exe_base = getattr(proc, "SectionBaseAddress", 0)
                try:
                    exe_base = int(exe_base)
                except Exception:
                    exe_base = 0
                peb = getattr(proc, "Peb", None)
                if (not exe_base or exe_base == 0) and peb:
                    img_base = getattr(peb, "ImageBaseAddress", 0)
                    if img_base:
                        exe_base = img_base

                # --- find the VAD covering the EXE base ---
                exe_vad = None
                try:
                    vad_root = proc.get_vad_root()
                    for vad in vad_root.traverse():
                        try:
                            if vad.get_start() <= exe_base < vad.get_end():
                                exe_vad = vad
                                break
                        except exceptions.InvalidAddressException:
                            pass
                except exceptions.InvalidAddressException:
                    pass
                # default placeholders
                file_name = "<no-VAD>"
                prot      = ""
                tag       = ""
                disasm    = []
                hex_lines = []
                dumped    = ""
                sha256    = ""
                yara_rule = ""
                vt_status = ""
                mitre     = self._map_to_mitre(0)

                if exe_vad:
                    # file name / protection / tag
                    fn_obj = exe_vad.get_file_name()
                    file_name = ("<Non-File Backed Region>"
                                 if fn_obj is None or isinstance(fn_obj, NotApplicableValue)
                                 else str(fn_obj))
                    prot = exe_vad.get_protection(
                        vadinfo.VadInfo.protect_values(
                            self.context,
                            kernel.layer_name,
                            kernel.symbol_table_name,
                        ),
                        vadinfo.winnt_protections,
                    ) or ""
                    tag = exe_vad.get_tag() or ""

                    # disassemble & hex‑dump first 64 bytes
                    ep, data, disasm = self._dump_and_disassemble(self.context, proc, exe_vad)
                    if data:
                        for i in range(0, len(data), 16):
                            chunk = data[i : i + 16]
                            hex_str = " ".join(f"{b:02x}" for b in chunk)
                            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                            hex_lines.append(f"{ep + i:08x}  {hex_str:<48}  {ascii_str}")

                    # dump the first page
                    dumped, sha256, raw = self._dump_memory(self.context, proc, exe_base, pid)
                    if dump_dir and dumped:
                        # 1) Correct file‑backed detection
                        fn_obj = exe_vad.get_file_name()
                        if fn_obj is not None and not isinstance(fn_obj, NotApplicableValue):
                            file_backed = True
                        else:
                            file_backed = False
                            vollog.warning(
                                f"No file‑backed VAD for PID {pid} ({name}) at 0x{exe_base:08x}; "
                                "marking dump as Suspicious"
                            )

                        # 2) Build label, address and filename
                        label   = "Genuine" if file_backed else "Suspicious"
                        addr_str = f"{exe_base:08x}"
                        new_name = f"{label}_{name}_{addr_str}_Image.dmp"
                        new_path = os.path.join(dump_dir, new_name)

                        # 3) Move into place, logging on success or failure
                        try:
                            os.replace(dumped, new_path)
                            vollog.info(f"Wrote {label.lower()} memory page to {new_path}")
                        except Exception as e:
                            vollog.warning(f"Failed to rename dump {dumped} → {new_path}: {e}")
                            new_path = dumped
                        dumped = new_path
                        
                    if do_yara and raw:
                        yara_rule = self._generate_yara_rule(raw, sha256)
                    if do_vt and sha256:
                        vt_status = self._query_virustotal(sha256)
                        
                mitre = mitre_field

                # assemble the 18‑field tuple
                full_row = (
                    pid,                             # PID
                    name,                            # Process Name
                    ppid,                            # Parent PID
                    desc,                            # Hollow Type
                    cmdline,                         # Command Line (PEB)
                    peb_base,                        # Base Address (PEB)
                    file_name,                       # VAD Filename
                    format_hints.Hex(exe_base),      # VAD Base Address
                    format_hints.Hex(
                        exe_vad.get_end() - exe_vad.get_start()
                    ) if exe_vad else format_hints.Hex(0),  # VAD Size
                    prot,                            # VAD Protection
                    tag,                             # VAD Tag
                    "\n".join(disasm),               # Disassembly
                    "\n".join(hex_lines),            # Hex Dump
                    dumped or "",                    # Dump Path
                    sha256 or "",                    # SHA256 Hash
                    yara_rule.strip(),               # YARA Rule
                    vt_status.strip(),               # VirusTotal Result
                    mitre                            # MITRE ATT&CK
                )
                results.append(full_row)
                
        # ───────────── file exports ─────────────
        if html_path:
            self._generate_html_report(results, html_path)
        if csv_path:
            self._generate_csv_report(results, csv_path)

        # prepare export data: drop the banner row
        export_results = [r for r in results if r != banner_row]
        
        if json_path:
            self._generate_json_report(export_results, json_path)
        if do_yara:
            self._write_yara_batch(export_results)


        return renderers.TreeGrid(
            columns,
            ((0, r) for r in results)
        )
