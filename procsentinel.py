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
        """
        Identify singleton‐process anomalies, but treat explorer.exe specially:
        if explorer.exe is run out of C:\\Windows, flag duplicates; otherwise ignore.
        """
        singleton_processes = {
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "lsass.exe", "explorer.exe", "taskhostw.exe", "dwm.exe", "spoolsv.exe",
            "userinit.exe", "logonui.exe", "audiodg.exe",
        }
        behavior_anomalies: list[tuple[int, str, any]] = []
        singleton_entries: dict[str, list[tuple[int, int, interfaces.objects.ObjectInterface]]] = {}
        pid_map = {int(p.UniqueProcessId): p for p in proc_list}

        # 1) Gather all instances of each “singleton” candidate
        for proc in proc_list:
            try:
                name = utility.array_to_string(proc.ImageFileName).strip("\x00").lower()
            except exceptions.InvalidAddressException:
                continue
            if name in singleton_processes:
                pid  = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                singleton_entries.setdefault(name, []).append((pid, ppid, proc))

        # 2) Evaluate each group
        for name, entries in singleton_entries.items():
            count = len(entries)

            # Special rule for csrss.exe
            if name == "csrss.exe":
                # allow up to 2 instances from System32
                if count <= 2:
                    continue

                # more than 2 running → inspect each one
                for pid, _, proc in entries:
                    # get on‑disk path
                    proc_path = "<missing>"
                    try:
                        peb = proc.Peb
                        proc_path = peb.ProcessParameters.ImagePathName.get_string().lower()
                    except Exception:
                        try:
                            proc_path = proc.get_process_path().lower()
                        except Exception:
                            pass
                        
                    # get on‑disk path
                    proc_path = proc_path.lower()
                    # figure out the in‐memory VAD for this csrss.exe instance
                    exe_base = getattr(proc, "SectionBaseAddress", 0)
                    try:
                        # fall back to PEB base if SectionBaseAddress is 0
                        if (not exe_base or exe_base == 0) and proc.Peb:
                            exe_base = proc.Peb.ImageBaseAddress or 0
                    except Exception:
                        pass

                    exe_vad = None
                    try:
                        for vad in proc.get_vad_root().traverse():
                            if vad.get_start() <= exe_base < vad.get_end():
                                exe_vad = vad
                                break
                    except exceptions.InvalidAddressException:
                        pass
                    # get VAD filename
                    vad_fn = exe_vad.get_file_name() if exe_vad else None
                    vad_path = str(vad_fn).lower() if vad_fn else ""

                    # skip if either the PEB path or the VAD filename is under System32
                    if (proc_path.startswith((r"c:\windows\system32", r"\windows\system32"))
                        or vad_path.startswith(r"\windows\system32")):
                        continue  # do NOT flag

                    # otherwise, flag as suspicious
                    desc = "SUSPICIOUS->INVESTIGATE (Excess csrss instances outside System32)"
                    behavior_anomalies.append((pid, desc, exe_vad))

                continue

            if name == "taskhostw.exe" and count <= 2 and len({pp for _, pp, _ in entries}) == 1:
                continue

            # Explorer.exe: only flag those not under C:\Windows
            if name == "explorer.exe":
                for pid, _, proc in entries:
                    # 1) Get on‑disk path
                    proc_path = "<missing>"
                    try:
                        proc_path = proc.Peb.ProcessParameters.ImagePathName.get_string()
                    except Exception:
                        try:
                            proc_path = proc.get_process_path() or proc_path
                        except Exception:
                            pass
                    proc_path = proc_path.lower()

                    # 2) Locate its VAD and filename
                    exe_base = getattr(proc, "SectionBaseAddress", 0) or getattr(proc.Peb, "ImageBaseAddress", 0)
                    exe_vad = None
                    try:
                        for vad in proc.get_vad_root().traverse():
                            if vad.get_start() <= exe_base < vad.get_end():
                                exe_vad = vad
                                break
                    except Exception:
                        pass
                    if exe_vad is None:
                        try:
                            exe_vad = next(proc.get_vad_root().traverse())
                        except Exception:
                            exe_vad = None

                    vad_fn = ""
                    if exe_vad:
                        fn_obj = exe_vad.get_file_name()
                        if fn_obj and not isinstance(fn_obj, NotApplicableValue):
                            vad_fn = str(fn_obj).lower()

                    # 3) Skip any explorer.exe whose PEB path or VAD filename is under C:\Windows
                    if (proc_path.startswith(r"c:\windows") or vad_fn.startswith(r"\windows")):
                        continue

                    # 4) Otherwise, flag it
                    desc = "SUSPICIOUS->INVESTIGATE (Multiple Instances of Explorer Outside C:\\Windows)"
                    if exe_vad:
                        behavior_anomalies.append((pid, desc, exe_vad))
                continue

            # For all others: if <=1, no issue; else mark all but lowest‐PID as suspicious
            if count <= 1:
                continue

            # sort by PID, drop the first (authentic), flag the rest
            entries_sorted = sorted(entries, key=lambda x: x[0])
            for pid, _, proc in entries_sorted[1:]:
                desc = "SUSPICIOUS->INVESTIGATE (Multiple Instances of Singleton Process)"
                exe_base = getattr(proc, "SectionBaseAddress", 0)
                try:
                    if (not exe_base or exe_base == 0) and proc.Peb:
                        exe_base = proc.Peb.ImageBaseAddress or 0
                except Exception:
                    pass

                exe_vad = None
                try:
                    for vad in proc.get_vad_root().traverse():
                        if vad.get_start() <= exe_base < vad.get_end():
                            exe_vad = vad
                            break
                except Exception:
                    pass

                if exe_vad is None:
                    try:
                        exe_vad = next(proc.get_vad_root().traverse())
                    except Exception:
                        exe_vad = None

                if exe_vad:
                    behavior_anomalies.append((pid, desc, exe_vad))

        return behavior_anomalies


        vollog.debug(f"[detect‑anomaly] total anomalies → {len(behavior_anomalies)}")

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
        
    def _generate_html_report(self, hollow_rows, anomaly_rows, html_path):
        headers = [h for h, _ in self.columns]
        anomaly_headers = headers.copy()
        anomaly_headers[3] = "Anomaly Type"
        template = Template(
        """
        <html><head><title>Process Sentinel Report</title></head><body>
          <h2>Hollowed/Injected Processes</h2>
          <table border="1" width="100%">
            <tr>{% for h in headers %}<th>{{ h }}</th>{% endfor %}</tr>
            {% if hollow_rows %}
              {% for r in hollow_rows %}
                <tr>{% for c in r %}<td>{{ c or 'Not Detected' }}</td>{% endfor %}</tr>
              {% endfor %}
            {% else %}
              <tr><td colspan="{{ col_count }}">No Result under this Category</td></tr>
            {% endif %}
          </table>

          <h2>PROCESS‑ANOMALIES</h2>
          <table border="1" width="100%">
            <tr>{% for h in anomaly_headers %}<th>{{ h }}</th>{% endfor %}</tr>
            {% if anomaly_rows %}
              {% for r in anomaly_rows %}
                <tr>{% for c in r %}<td>{{ c or 'Not Detected' }}</td>{% endfor %}</tr>
              {% endfor %}
            {% else %}
              <tr><td colspan="{{ col_count }}">No Result under this Category</td></tr>
            {% endif %}
          </table>
          <footer>Memory Analysis Report Generated By Process Sentinel Plugin</footer>
        </body></html>
        """
        )
        with open(html_path, "w") as f:
            f.write(template.render(
                headers=headers,
                anomaly_headers=anomaly_headers,
                hollow_rows=hollow_rows,
                anomaly_rows=anomaly_rows,
                col_count=len(headers)
            ))

    def _generate_csv_report(self, hollow_rows, anomaly_rows, csv_path):
        headers = [h for h, _ in self.columns]
        anomaly_headers = headers.copy()
        anomaly_headers[3] = "Anomaly Type"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Hollowed/Injected section
            writer.writerow(headers)
            writer.writerow([])
            writer.writerow(["Hollowed/Injected Processes"] + [""]*(len(headers)-1))
            if hollow_rows:
                for r in hollow_rows:
                    writer.writerow([c or "Not Detected" for c in r])
            else:
                writer.writerow(["No Result under this Category"] + [""]*(len(headers)-1))

            # PROCESS-ANOMALIES section
            writer.writerow([])
            writer.writerow(anomaly_headers)
            if anomaly_rows:
                for r in anomaly_rows:
                    writer.writerow([c or "Not Detected" for c in r])
            else:
                writer.writerow(["No Result under this Category"] + [""]*(len(headers)-1))

            # Footer note
            writer.writerow([])
            writer.writerow(["Memory Analysis Report Generated By Process Sentinel Plugin"])

    def _generate_json_report(self, hollow_rows, anomaly_rows, json_path):
        def _clean(val):
            if val is None or val == "" or isinstance(val, renderers.NotApplicableValue):
                return "Not Detected"
            if isinstance(val, (str, int, float, bool)):
                return val
            if isinstance(val, format_hints.MultiTypeData):
                return str(val)
            return str(val)

        # grab the header names from your columns definition
        column_keys = [h for h, _ in self.columns]

        # build list of dicts for each section
        hi = []
        if hollow_rows:
            for row in hollow_rows:
                hi.append({ column_keys[i]: _clean(row[i]) for i in range(len(column_keys)) })
        else:
            hi = [{"message": "No Result under this Category"}]

        pa = []
        if anomaly_rows:
            for row in anomaly_rows:
                pa.append({ column_keys[i]: _clean(row[i]) for i in range(len(column_keys)) })
        else:
            pa = [{"message": "No Result under this Category"}]

        out = {
            "hollowed_injected": hi,
            "process_anomalies": pa,
            "footer_note": "Memory Analysis Report Generated By Process Sentinel Plugin"
        }

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
        dump_info = {}
        dumped_addresses = {}
        dump_dedup = {}
        hollow_rows = []
        anomaly_rows = []

        kernel = self.context.modules[self.config["kernel"]]
        filter_pids = self.config.get("pid")
        cmd_filter = (self.config.get("cmd_filter") or "").lower()
        html_path = self.config.get("html_report")
        csv_path = self.config.get("csv_report")
        json_path = self.config.get("json_report")
        do_yara = self.config.get("yara_output", False)
        do_vt = self.config.get("check_virustotal", False)
        dump_dir = self.config.get("dump_dir")

        # define the report columns
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
        self.columns = columns

        try:
            proc_list = list(pslist.PsList.list_processes(self.context, self.config["kernel"]))
        except TypeError:
            proc_list = list(pslist.PsList.list_processes(
                self.context, kernel.layer_name, kernel.symbol_table_name
            ))

        anomaly_findings = self._detect_behavior_anomalies(proc_list)
        pid_map = {int(p.UniqueProcessId): p for p in proc_list}

        for proc in proc_list:
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            if filter_pids and pid not in filter_pids:
                continue

            name = utility.array_to_string(proc.ImageFileName)
            peb_info = self._get_peb_info(proc) or ("", 0)
            if cmd_filter and cmd_filter not in peb_info[0].lower():
                continue

            # only scans/injections here
            combined = (
                self._detect_hollowing_or_injection(proc)
                + self._scan_all_execute_vads(proc)
                + self._scan_blind_rwx_mz_vads(proc)
            )

            # behavior anomalies go only to anomaly_rows
            behavior = [(d, v) for (a_pid, d, v) in anomaly_findings if a_pid == pid]

            for finding_msg, vad in combined + behavior:
                if vad is None:
                    vollog.debug(f"[run] skipping “{finding_msg}” because VAD is None")
                    continue
                start = vad.get_start()
                size = vad.get_end() - start
                key = (pid, start)

                if key not in dump_info:
                    dumped, sha256, raw = self._dump_memory(self.context, proc, start, pid)
                    fn_obj = vad.get_file_name()
                    label = "Genuine" if fn_obj and not isinstance(fn_obj, NotApplicableValue) else "Suspicious"
                    new_name = f"{label}_{name}_{start:08x}_Image.dmp"
                    dedup_key = (pid, sha256, new_name)

                    if dedup_key in dump_dedup:
                        orig = dump_dedup[dedup_key]
                        info = dump_info[orig]
                        dump_path = dumped_addresses[orig]
                    else:
                        dump_dedup[dedup_key] = key
                        if dump_dir and dumped:
                            new_path = os.path.join(dump_dir, new_name)
                            try:
                                os.replace(dumped, new_path)
                            except OSError:
                                os.rename(dumped, new_path)
                            dump_path = new_path
                        else:
                            dump_path = dumped or ""

                        info = {"sha256": sha256 or "", "raw": raw, "dump_path": dump_path}
                        ep, data, disasm = self._dump_and_disassemble(self.context, proc, vad)
                        hex_lines = []
                        if data:
                            for i in range(0, len(data), 16):
                                chunk = data[i:i+16]
                                hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                                hex_lines.append(f"{ep+i:08x}  {hex_bytes:<48}  {ascii_str}")
                        info.update({
                            "disasm": disasm,
                            "hex_lines": hex_lines,
                            "prot": vad.get_protection(
                                vadinfo.VadInfo.protect_values(
                                    self.context, kernel.layer_name, kernel.symbol_table_name),
                                vadinfo.winnt_protections
                            ) or "",
                            "file_name": str(fn_obj) if fn_obj and not isinstance(fn_obj, NotApplicableValue) else "Memory‑only region (No VAD Mapping)",
                            "tag": vad.get_tag() or "",
                            "yara_rule": (self._generate_yara_rule(raw, sha256).strip() if do_yara and raw else ""),
                            "vt_status": (self._query_virustotal(sha256).strip() if do_vt and sha256 else "")
                        })
                        dump_info[key] = info
                        dumped_addresses[key] = dump_path
                else:
                    info = dump_info[key]
                    dump_path = dumped_addresses[key]

                cmdline, ba = peb_info
                base = format_hints.Hex(ba)
                row = (
                    pid, name, ppid, finding_msg,
                    cmdline, base,
                    info["file_name"],
                    format_hints.Hex(start),
                    format_hints.Hex(size),
                    info["prot"], info["tag"],
                    "\n".join(info["disasm"]),
                    "\n".join(info["hex_lines"]),
                    dump_path,
                    info["sha256"],
                    info["yara_rule"],
                    info["vt_status"],
                    "Masquerading - T1036"
                )
                if finding_msg.startswith("SUSPICIOUS->INVESTIGATE"):
                    anomaly_rows.append(row)
                else:
                    if finding_msg not in [d for (d,_) in behavior]:
                        # only scans/injections
                        hollow_rows.append(row)

        # prepare banner for console only
        banner = []
        for _, col_type in columns:
            if col_type is int:
                banner.append(BannerInt(0, "PROCESS‑ANOMALIES"))
            elif col_type is format_hints.Hex:
                banner.append(format_hints.Hex(0, "PROCESS‑ANOMALIES"))
            else:
                banner.append("PROCESS‑ANOMALIES")
        banner = tuple(banner)

        # Export reports (no banner in reports)
        if html_path:
            self._generate_html_report(hollow_rows, anomaly_rows, html_path)
        if csv_path:
            self._generate_csv_report(hollow_rows, anomaly_rows, csv_path)
        if json_path:
            self._generate_json_report(hollow_rows, anomaly_rows, json_path)

        # Console output
        console_rows = []
        console_rows.extend(hollow_rows)
        if anomaly_rows:
            console_rows.append(banner)
            console_rows.extend(anomaly_rows)

        return renderers.TreeGrid(
            columns,
            chain(((0, r) for r in console_rows))
        )
