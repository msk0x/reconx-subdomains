"""
ReconX Subdomains

Advanced subdomain enumeration engine for offensive security,
attack surface mapping, and reconnaissance workflows.
"""

import base64
import concurrent.futures
import json
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
        self.timeout = 20

        self.api_keys = api_keys or {}

        self.found: Set[str] = set()

        self._lock = threading.Lock()

        self._sess = requests.Session()
        self._sess.headers.update({
            "User-Agent": UA
        })

    # ──────────────────────────────────────────────────────────────────────
    # Main Runner
    # ──────────────────────────────────────────────────────────────────────
    def run(
        self,
        bruteforce: bool = True,
        dns_wordlist: str = None,
        output_file: str = None,
    ) -> List[str]:

        console.print(
            f"  [cyan]Target:[/cyan] {self.domain}"
        )

        methods = [
            ("subfinder", self._subfinder),
            ("amass", self._amass_passive),
            ("assetfinder", self._assetfinder),
            ("crt.sh", self._crtsh),
            ("crt.sh v2", self._crtsh_v2),
            ("certspotter", self._certspotter),
            ("waybackurls", self._wayback),
            ("gau", self._gau),
            ("hackertarget", self._hackertarget),
            ("rapiddns", self._rapiddns),
            ("urlscan", self._urlscan),
            ("alienvault", self._alienvault),
            ("jldc", self._jldc),
            ("anubis", self._anubis),
            ("virustotal", self._virustotal),
            ("github", self._github_dork),
            ("bufferover", self._bufferover),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description:<20}[/cyan]"),
            TextColumn("[green]{task.fields[found]} found[/green]"),
            console=console,
        ) as progress:

            tasks = {
                name: progress.add_task(name, found=0)
                for name, _ in methods
            }

            for name, method in methods:
                try:
                    results = method()

                    if self.verbose:
                        console.print(
                            f"[yellow]{name} raw:[/yellow] "
                            f"{len(results)}"
                        )

                    with self._lock:
                        before = len(self.found)

                        for result in results:
                            result = (
                                result.strip()
                                .lower()
                                .lstrip("*.")
                            )

                            if self.domain in result:
                                self.found.add(result)

                        new = len(self.found) - before

                    progress.update(
                        tasks[name],
                        description=f"[dim]{name}[/dim]",
                        found=len(self.found),
                    )

                    if new:
                        console.print(
                            f"    [green]+{new}[/green] "
                            f"from {name}"
                        )

                except Exception as e:
                    progress.update(
                        tasks[name],
                        description=f"[red]{name} error[/red]",
                        found=len(self.found),
                    )

                    if self.verbose:
                        console.print(
                            f"[red]{name}: {e}[/red]"
                        )

        # ─── Bruteforce ────────────────────────────────────────────────
        if bruteforce and dns_wordlist:
            if Path(dns_wordlist).exists():

                console.print(
                    f"\n  [cyan]DNS Bruteforce:[/cyan] "
                    f"{dns_wordlist}"
                )

                brute = self._dns_bruteforce(dns_wordlist)

                before = len(self.found)

                self.found.update(brute)

                new = len(self.found) - before

                console.print(
                    f"    [green]+{new}[/green] "
                    f"from bruteforce"
                )

        # ─── Permutations ──────────────────────────────────────────────
        perms = self._permutations(list(self.found))

        if perms:
            console.print(
                f"\n  [cyan]Permutation validation:[/cyan] "
                f"{len(perms)} candidates"
            )

            valid = self._resolve_batch(perms)

            before = len(self.found)

            self.found.update(valid)

            new = len(self.found) - before

            if new:
                console.print(
                    f"    [green]+{new}[/green] "
                    f"from permutations"
                )

        # ─── Cleaning ─────────────────────────────────────────────────
        before_clean = len(self.found)

        clean = self._clean(self.found)

        if self.verbose:
            console.print(
                f"[yellow]before clean:[/yellow] "
                f"{before_clean}"
            )

            console.print(
                f"[yellow]after clean:[/yellow] "
                f"{len(clean)}"
            )

        # ─── Output ───────────────────────────────────────────────────
        if output_file:
            with open(output_file, "w") as f:
                f.write("\n".join(clean))

        return clean

    # ──────────────────────────────────────────────────────────────────────
    # Cleaning
    # ──────────────────────────────────────────────────────────────────────
    def _clean(self, subs: Set[str]) -> List[str]:
        clean = set()

        pattern = re.compile(
            rf"(?:[a-zA-Z0-9\-]+\.)+{re.escape(self.domain)}$"
        )

        for sub in subs:
            sub = (
                sub.strip()
                .lower()
                .rstrip(".")
            )

            sub = re.sub(
                r"^[*\.\s]+",
                "",
                sub,
            )

            if (
                sub
                and len(sub) < 255
                and pattern.search(sub)
            ):
                clean.add(sub)

        return sorted(clean)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _run_tool(self, cmd, timeout=180):
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                executable="/bin/bash",
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

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]Tool error:[/red] {e}"
                )

            return []

    def _get(self, url, timeout=None, json_resp=False):
        try:
            timeout = timeout or self.timeout

            response = self._sess.get(
                url,
                timeout=timeout,
            )

            if len(response.text) > 15_000_000:
                return None

            if response.ok:
                return (
                    response.json()
                    if json_resp
                    else response.text
                )

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]GET error:[/red] {e}"
                )

        return None

    # ──────────────────────────────────────────────────────────────────────
    # External Tools
    # ──────────────────────────────────────────────────────────────────────
    def _subfinder(self):
        tool = find_tool("subfinder")

        if not tool:
            return []

        results = self._run_tool(
            f"{tool} -d {self.domain} -silent -all",
            300,
        )

        if self.verbose:
            console.print(
                f"[yellow]subfinder raw:[/yellow] "
                f"{len(results)}"
            )

        return results

    def _amass_passive(self):
        tool = find_tool("amass")

        if not tool:
            return []

        return self._run_tool(
            f"{tool} enum -passive -d {self.domain}",
            300,
        )

    def _assetfinder(self):
        tool = find_tool("assetfinder")

        if not tool:
            return []

        return self._run_tool(
            f"{tool} --subs-only {self.domain}"
        )

    def _wayback(self):
        tool = find_tool("waybackurls")

        if not tool:
            return []

        lines = self._run_tool(
            f'echo "{self.domain}" | {tool}',
            120,
        )

        return self._extract_subs(lines)

    def _gau(self):
        tool = find_tool("gau")

        if not tool:
            return []

        lines = self._run_tool(
            f"{tool} {self.domain}",
            180,
        )

        return self._extract_subs(lines)

    # ──────────────────────────────────────────────────────────────────────
    # HTTP Sources
    # ──────────────────────────────────────────────────────────────────────
    def _crtsh(self):
        subs = set()

        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                headers={"User-Agent": UA},
                timeout=self.timeout,
            )

            if response.ok:
                data = response.json()

                for entry in data:
                    for item in entry.get(
                        "name_value",
                        ""
                    ).splitlines():

                        item = (
                            item.strip()
                            .lstrip("*.")
                        )

                        if self.domain in item:
                            subs.add(item)

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]crt.sh:[/red] {e}"
                )

        return list(subs)

    def _crtsh_v2(self):
        subs = set()

        try:
            response = requests.get(
                f"https://crt.sh/?q=%.%.{self.domain}&output=json",
                headers={"User-Agent": UA},
                timeout=self.timeout,
            )

            if response.ok:
                data = response.json()

                for entry in data:
                    for item in entry.get(
                        "name_value",
                        ""
                    ).splitlines():

                        item = (
                            item.strip()
                            .lstrip("*.")
                        )

                        if self.domain in item:
                            subs.add(item)

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]crt.sh v2:[/red] {e}"
                )

        return list(subs)

    def _certspotter(self):
        subs = set()

        try:
            response = requests.get(
                "https://api.certspotter.com/v1/issuances"
                f"?domain={self.domain}"
                "&include_subdomains=true"
                "&expand=dns_names",
                timeout=self.timeout,
                headers={"User-Agent": UA},
            )

            if response.ok:
                for entry in response.json():
                    for name in entry.get(
                        "dns_names",
                        []
                    ):

                        name = name.lstrip("*.")

                        if self.domain in name:
                            subs.add(name)

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]certspotter:[/red] {e}"
                )

        return list(subs)

    def _hackertarget(self):
        text = self._get(
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        )

        if not text:
            return []

        return [
            line.split(",")[0]
            for line in text.splitlines()
            if self.domain in line
        ]

    def _rapiddns(self):
        text = self._get(
            f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        )

        if not text:
            return []

        matches = re.findall(
            rf"[a-zA-Z0-9_\-\.]+\.{re.escape(self.domain)}",
            text,
        )

        return list(set(matches))

    def _urlscan(self):
        subs = set()

        try:
            response = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}",
                timeout=self.timeout,
                headers={"User-Agent": UA},
            )

            if response.ok:
                for result in response.json().get(
                    "results",
                    []
                ):

                    page = result.get("page", {})
                    domain = page.get("domain")

                    if domain and self.domain in domain:
                        subs.add(domain)

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]urlscan:[/red] {e}"
                )

        return list(subs)

    def _alienvault(self):
        subs = set()

        try:
            response = requests.get(
                f"https://otx.alienvault.com/api/v1/"
                f"indicators/domain/{self.domain}/passive_dns",
                timeout=self.timeout,
                headers={"User-Agent": UA},
            )

            if response.ok:
                for item in response.json().get(
                    "passive_dns",
                    []
                ):

                    hostname = item.get("hostname")

                    if hostname and self.domain in hostname:
                        subs.add(hostname)

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]alienvault:[/red] {e}"
                )

        return list(subs)

    def _jldc(self):
        text = self._get(
            f"https://jldc.me/anubis/subdomains/{self.domain}"
        )

        if not text:
            return []

        try:
            data = json.loads(text)

            return [
                item
                for item in data
                if self.domain in item
            ]

        except Exception:
            return []

    def _anubis(self):
        return self._jldc()

    def _virustotal(self):
        subs = set()

        api_key = self.api_keys.get(
            "virustotal"
        )

        try:
            headers = {
                "User-Agent": UA
            }

            if api_key:
                headers["x-apikey"] = api_key

                response = requests.get(
                    f"https://www.virustotal.com/api/v3/"
                    f"domains/{self.domain}/subdomains?limit=1000",
                    headers=headers,
                    timeout=self.timeout,
                )

                if response.ok:
                    for item in response.json().get(
                        "data",
                        []
                    ):

                        subs.add(
                            item.get("id", "")
                        )

            else:
                response = requests.get(
                    f"https://www.virustotal.com/ui/"
                    f"domains/{self.domain}/subdomains?limit=40",
                    headers=headers,
                    timeout=self.timeout,
                )

                if response.ok:
                    for item in response.json().get(
                        "data",
                        []
                    ):

                        subs.add(
                            item.get("id", "")
                        )

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]virustotal:[/red] {e}"
                )

        return list(subs)

    def _bufferover(self):
        subs = set()

        try:
            response = requests.get(
                f"https://dns.bufferover.run/dns?q=.{self.domain}",
                timeout=self.timeout,
                headers={"User-Agent": UA},
            )

            if response.ok:
                data = response.json()

                for entry in data.get(
                    "FDNS_A",
                    []
                ):
                    try:
                        host = entry.split(",")[1]

                        if self.domain in host:
                            subs.add(host)

                    except Exception:
                        continue

            time.sleep(0.3)

        except Exception as e:
            if self.verbose:
                console.print(
                    f"[red]bufferover:[/red] {e}"
                )

        return list(subs)

    def _github_dork(self):
        subs = set()

        token = self.api_keys.get("github")

        if not token:
            return []

        headers = {
            "Authorization": f"token {token}",
            "User-Agent": "ReconX",
        }

        queries = [
            f'"{self.domain}"',
            f"site:{self.domain}",
        ]

        for query in queries:
            try:
                response = requests.get(
                    f"https://api.github.com/search/code"
                    f"?q={requests.utils.quote(query)}"
                    f"&per_page=50",
                    headers=headers,
                    timeout=self.timeout,
                )

                if response.status_code == 403:
                    break

                if response.ok:
                    for item in response.json().get(
                        "items",
                        []
                    ):

                        content_url = item.get("url")

                        if not content_url:
                            continue

                        try:
                            content_response = requests.get(
                                content_url,
                                headers=headers,
                                timeout=15,
                            )

                            if content_response.ok:
                                raw = base64.b64decode(
                                    content_response.json().get(
                                        "content",
                                        ""
                                    )
                                ).decode(
                                    "utf-8",
                                    errors="ignore"
                                )

                                matches = re.findall(
                                    rf"[a-zA-Z0-9_\-\.]+"
                                    rf"\.{re.escape(self.domain)}",
                                    raw,
                                )

                                subs.update(matches)

                        except Exception:
                            continue

                time.sleep(1)

            except Exception as e:
                if self.verbose:
                    console.print(
                        f"[red]github:[/red] {e}"
                    )

        return list(subs)

    # ──────────────────────────────────────────────────────────────────────
    # DNS Bruteforce
    # ──────────────────────────────────────────────────────────────────────
    def _dns_bruteforce(self, wordlist):
        dnsx = find_tool("dnsx")

        tmp = Path(
            tempfile.mktemp(
                suffix="_dns.txt"
            )
        )

        with open(wordlist) as f:
            words = [
                line.strip()
                for line in f
                if line.strip()
                and not line.startswith("#")
            ]

        with open(tmp, "w") as f:
            for word in words:
                f.write(
                    f"{word}.{self.domain}\n"
                )

        results = set()

        if dnsx:
            cmd = (
                f"{dnsx} -l {tmp} "
                f"-silent -resp-only "
                f"-t {min(self.threads * 2, 100)}"
            )

            results.update(
                self._run_tool(
                    cmd,
                    timeout=600
                )
            )

        else:
            console.print(
                "[yellow]dnsx not found "
                "— fallback resolver enabled[/yellow]"
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

    # ──────────────────────────────────────────────────────────────────────
    # DNS Resolution
    # ──────────────────────────────────────────────────────────────────────
    def _resolve_batch(
        self,
        hosts,
        max_workers=50,
    ):

        valid = set()

        lock = threading.Lock()

        def resolve(host):
            try:
                socket.getaddrinfo(
                    host,
                    None,
                )

                with lock:
                    valid.add(host)

            except Exception:
                return

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as executor:
            executor.map(
                resolve,
                hosts,
            )

        return valid

    # ──────────────────────────────────────────────────────────────────────
    # Permutations
    # ──────────────────────────────────────────────────────────────────────
    def _permutations(self, found_subs):
        """
        Generate lightweight realistic permutations
        from first-level labels only.

        Avoids recursive/nested permutation explosions.
        """

        mutations = {
            "dev",
            "staging",
            "stage",
            "prod",
            "test",
            "beta",
            "api",
        }

        base_labels = set()

        for sub in found_subs:
            sub = sub.replace(
                f".{self.domain}",
                ""
            )

            # only first-level labels
            if "." not in sub:
                base_labels.add(sub)

        candidates = set()

        for label in base_labels:
            label = label.strip()

            if not label:
                continue

            for mutation in mutations:

                if label == mutation:
                    continue

                candidates.add(
                    f"{label}-{mutation}.{self.domain}"
                )

                candidates.add(
                    f"{mutation}-{label}.{self.domain}"
                )

        return list(
            candidates - set(found_subs)
        )

    # ──────────────────────────────────────────────────────────────────────
    # URL Extraction Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _extract_subs(self, lines):
        subs = set()

        regex = re.compile(
            rf"[a-zA-Z0-9_\-\.]+\.{re.escape(self.domain)}"
        )

        for line in lines:
            matches = regex.findall(line)

            for match in matches:
                subs.add(
                    match.strip().lower()
                )

        return list(subs)


if __name__ == "__main__":
    enum = SubdomainEnumerator(
        domain="example.com",
        verbose=True,
    )

    results = enum.run()

    print("\n".join(results))
