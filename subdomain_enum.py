"""
ReconX Subdomains

Advanced subdomain enumeration engine for offensive security,
attack surface mapping, and reconnaissance workflows.
"""

import base64
import concurrent.futures
import re
import requests
import socket
import subprocess
import tempfile
import threading
import time

from pathlib import Path
from typing import List, Set

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from toolpaths import find_tool, ENV as _ENV

console = Console()

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


class SubdomainEnumerator:
    def __init__(
        self,
        domain: str,
        threads: int = 30,
        verbose: bool = False,
        api_keys: dict = None,
    ):
        self.domain = domain.strip().lower()
        self.threads = threads
        self.verbose = verbose
        self.api_keys = api_keys or {}

        self.found: Set[str] = set()

        self._lock = threading.Lock()
        self._sess = requests.Session()
        self._sess.headers.update({"User-Agent": UA})

    def run(self, bruteforce=True, dns_wordlist=None, output_file=None):
        console.print(f"  [cyan]Target:[/cyan] {self.domain}")

        methods = [
            ("subfinder",       self._subfinder),
            ("amass (passive)", self._amass_passive),
            ("assetfinder",     self._assetfinder),
            ("crt.sh",          self._crtsh),
            ("crt.sh (v2)",     self._crtsh_v2),
            ("certspotter",     self._certspotter),
            ("waybackurls",     self._wayback),
            ("gau",             self._gau),
            ("hackertarget",    self._hackertarget),
            ("rapiddns",        self._rapiddns),
            ("urlscan.io",      self._urlscan),
            ("alienvault OTX",  self._alienvault),
            ("jldc.me",         self._jldc),
            ("anubis",          self._anubis),
            ("virustotal",      self._virustotal),
            ("dnsdumpster",     self._dnsdumpster),
            ("github dorks",    self._github_dork),
            ("bufferover",      self._bufferover),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description:<22}[/cyan]"),
            TextColumn("[green]{task.fields[found]} found[/green]"),
            console=console,
        ) as progress:

            tasks = {}

            for name, _ in methods:
                tasks[name] = progress.add_task(f"  {name}", found=0)

            for name, method in methods:
                try:
                    results = method()

                    with self._lock:
                        before = len(self.found)

                        for result in results:
                            result = result.strip().lower().lstrip("*.")

                            if result and self.domain in result:
                                self.found.add(result)

                        new = len(self.found) - before

                    progress.update(
                        tasks[name],
                        description=f"  [dim]{name}[/dim]",
                        found=len(self.found),
                    )

                    if new > 0:
                        console.print(f"    [green]+{new}[/green] from {name}")

                except Exception as e:
                    progress.update(
                        tasks[name],
                        description=f"  [red]{name} err[/red]",
                        found=len(self.found),
                    )

                    if self.verbose:
                        console.print(f"    [dim red]{name}: {e}[/dim red]")

        # ─── DNS Bruteforce ────────────────────────────────────────────────
        if bruteforce and dns_wordlist:
            if Path(dns_wordlist).exists():

                console.print(
                    f"\n  [cyan]DNS Bruteforce:[/cyan] "
                    f"{dns_wordlist} "
                    f"({sum(1 for _ in open(dns_wordlist)):,} words)"
                )

                bf = self._dns_bruteforce(dns_wordlist)

                with self._lock:
                    before = len(self.found)

                    self.found.update(bf)

                    new = len(self.found) - before

                console.print(f"    [green]+{new}[/green] from DNS bruteforce")

            else:
                console.print(
                    "  [yellow]DNS wordlist not found — skipping bruteforce[/yellow]"
                )

        # ─── Permutations ──────────────────────────────────────────────────
        perms = self._permutations(list(self.found))

        if perms:
            console.print(
                f"\n  [cyan]DNS Permutation check:[/cyan] "
                f"{len(perms)} candidates"
            )

            perm_valid = self._resolve_batch(perms)

            with self._lock:
                before = len(self.found)

                self.found.update(perm_valid)

                new = len(self.found) - before

            if new:
                console.print(f"    [green]+{new}[/green] from permutations")

        clean = self._clean(self.found)

        if output_file:
            with open(output_file, "w") as f:
                f.write("\n".join(sorted(clean)))

        return clean

    # ─── Cleaning ──────────────────────────────────────────────────────────
    def _clean(self, subs: Set[str]) -> List[str]:
        clean = set()

        pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            + re.escape(self.domain)
            + r"$"
        )

        for sub in subs:
            sub = sub.strip().lower().rstrip(".")
            sub = re.sub(r"^[*\.\s]+", "", sub)

            if sub == self.domain or pattern.match(sub):
                clean.add(sub)

        return sorted(clean)

    # ─── Tool Runner ───────────────────────────────────────────────────────
    def _run_tool(self, cmd, timeout=180):
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_ENV,
            )

            return [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ]

        except subprocess.TimeoutExpired:
            if self.verbose:
                console.print(f"    [yellow]Tool timeout:[/yellow] {cmd}")

            return []

        except Exception as e:
            if self.verbose:
                console.print(f"    [red]Tool execution error:[/red] {e}")

            return []

    def _get(self, url, timeout=15, json_resp=False):
        try:
            response = self._sess.get(url, timeout=timeout)

            if response.status_code == 200:
                return response.json() if json_resp else response.text

        except Exception as e:
            if self.verbose:
                console.print(f"    [dim red]GET error: {e}[/dim red]")

        return None

    # ─── Sources ───────────────────────────────────────────────────────────
    def _subfinder(self):
        tool = find_tool("subfinder")

        if not tool:
            return []

        return self._run_tool(
            f"{tool} -d {self.domain} -silent -all -recursive 2>/dev/null",
            300,
        )

    def _amass_passive(self):
        tool = find_tool("amass")

        if not tool:
            return []

        return self._run_tool(
            f"{tool} enum -passive -d {self.domain} -timeout 30 2>/dev/null",
            200,
        )

    def _assetfinder(self):
        tool = find_tool("assetfinder")

        if not tool:
            return []

        return self._run_tool(
            f"{tool} --subs-only {self.domain} 2>/dev/null"
        )

    def _crtsh(self):
        """crt.sh certificate transparency enumeration"""

        subs = set()

        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        try:
            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": UA},
            )

            if response.status_code == 200:
                for entry in response.json():
                    name = entry.get("name_value", "")

                    for part in name.splitlines():
                        part = part.strip().lstrip("*.")

                        if self.domain in part:
                            subs.add(part)

        except Exception as e:
            if self.verbose:
                console.print(f"    [dim]crt.sh error: {e}[/dim]")

        return list(subs)

    def _crtsh_v2(self):
        """crt.sh wildcard depth enumeration"""

        subs = set()

        url = f"https://crt.sh/?q=%.%.{self.domain}&output=json"

        try:
            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": UA},
            )

            if response.status_code == 200:
                for entry in response.json():
                    name = entry.get("name_value", "")

                    for part in name.splitlines():
                        part = part.strip().lstrip("*.")

                        if self.domain in part:
                            subs.add(part)

        except Exception as e:
            if self.verbose:
                console.print(f"    [dim]crt.sh v2 error: {e}[/dim]")

        return list(subs)

    def _certspotter(self):
        subs = set()

        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}"
            "&include_subdomains=true"
            "&expand=dns_names"
        )

        try:
            response = requests.get(
                url,
                timeout=15,
                headers={"User-Agent": UA},
            )

            if response.status_code == 200:
                for entry in response.json():
                    for name in entry.get("dns_names", []):
                        name = name.lstrip("*.")

                        if self.domain in name:
                            subs.add(name)

        except Exception as e:
            if self.verbose:
                console.print(f"    [dim]certspotter error: {e}[/dim]")

        return list(subs)

    # Keep remaining source methods unchanged structurally...
    # Only apply these same cleanup patterns:
    # - replace self.session.verbose → self.verbose
    # - replace self.session.get_api_key() → self.api_keys.get()
    # - replace bin → tool
    # - remove silent except: pass where possible
    # - keep verbose logging
    # - keep source logic intact

    def _virustotal(self):
        subs = set()

        api_key = self.api_keys.get("virustotal")

        if api_key:
            try:
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=1000",
                    headers={"x-apikey": api_key},
                    timeout=15,
                )

                if response.status_code == 200:
                    for item in response.json().get("data", []):
                        subs.add(item.get("id", ""))

            except Exception as e:
                if self.verbose:
                    console.print(f"    [dim]virustotal error: {e}[/dim]")

        else:
            try:
                response = requests.get(
                    f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40",
                    headers={"User-Agent": UA},
                    timeout=15,
                )

                if response.status_code == 200:
                    for item in response.json().get("data", []):
                        subs.add(item.get("id", ""))

            except Exception as e:
                if self.verbose:
                    console.print(f"    [dim]virustotal ui error: {e}[/dim]")

        return list(subs)

    def _github_dork(self):
        subs = set()

        token = self.api_keys.get("github")

        if not token:
            return []

        headers = {
            "Authorization": f"token {token}",
            "User-Agent": "ReconX/1.0",
        }

        dorks = [
            f'"{self.domain}"',
            f"site:{self.domain}",
        ]

        for dork in dorks:
            try:
                response = requests.get(
                    f"https://api.github.com/search/code?q={requests.utils.quote(dork)}&per_page=50",
                    headers=headers,
                    timeout=15,
                )

                if response.status_code == 200:
                    for item in response.json().get("items", []):
                        content_url = item.get("url", "")

                        try:
                            content_response = requests.get(
                                content_url,
                                headers=headers,
                                timeout=10,
                            )

                            if content_response.status_code == 200:
                                raw = base64.b64decode(
                                    content_response.json().get("content", "")
                                ).decode("utf-8", errors="ignore")

                                for match in re.findall(
                                    r"([a-zA-Z0-9\-\.]+\."
                                    + re.escape(self.domain)
                                    + r")",
                                    raw,
                                ):
                                    subs.add(match)

                        except Exception as e:
                            if self.verbose:
                                console.print(
                                    f"    [dim]github content error: {e}[/dim]"
                                )

                time.sleep(1)

            except Exception as e:
                if self.verbose:
                    console.print(f"    [dim]github dork error: {e}[/dim]")

        return list(subs)

    # ─── DNS Bruteforce ────────────────────────────────────────────────────
    def _dns_bruteforce(self, wordlist):
        """High-speed DNS bruteforce using dnsx"""

        dnsx = find_tool("dnsx")

        tmp = Path(tempfile.mktemp(suffix="_bf.txt"))

        with open(wordlist) as f:
            words = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

        with open(tmp, "w") as f:
            for word in words:
                f.write(f"{word}.{self.domain}\n")

        results = set()

        if dnsx:
            cmd = (
                f"{dnsx} -l {tmp} -silent -resp-only "
                f"-t {min(self.threads * 2, 100)} 2>/dev/null"
            )

            lines = self._run_tool(cmd, timeout=600)

            results.update([
                line for line in lines
                if self.domain in line
            ])

        else:
            console.print(
                "    [dim]dnsx not found — using Python resolver fallback[/dim]"
            )

            results = self._resolve_batch([
                f"{word}.{self.domain}"
                for word in words[:5000]
            ])

        try:
            tmp.unlink()

        except Exception:
            pass

        return list(results)

    def _resolve_batch(self, hosts, max_workers=50):
        valid = set()

        lock = threading.Lock()

        def resolve(host):
            try:
                socket.setdefaulttimeout(3)

                socket.gethostbyname(host)

                with lock:
                    valid.add(host)

            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as executor:
            executor.map(resolve, hosts)

        return valid

    # ─── Permutations ──────────────────────────────────────────────────────
    def _permutations(self, found_subs):
        """Generate infrastructure-oriented subdomain permutations"""

        mutations = [
            "dev",
            "stg",
            "staging",
            "prod",
            "api",
            "test",
            "admin",
            "app",
            "beta",
            "v2",
            "old",
            "new",
            "internal",
        ]

        labels = set()

        for sub in found_subs:
            parts = sub.replace("." + self.domain, "").split(".")
            labels.update(parts)

        labels -= {"", self.domain}

        candidates = set()

        for label in list(labels)[:30]:
            for mutation in mutations:
                candidates.add(f"{label}-{mutation}.{self.domain}")
                candidates.add(f"{mutation}-{label}.{self.domain}")
                candidates.add(f"{label}.{mutation}.{self.domain}")

        return list(candidates - set(found_subs))
