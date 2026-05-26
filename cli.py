#!/usr/bin/env python3

"""
ReconX Subdomains - CLI Interface

Command-line interface for:
- subdomain enumeration
- DNS bruteforce
- passive reconnaissance
- validation workflows
- reconnaissance automation
"""

import argparse
import json
import sys
import time

from pathlib import Path

from rich.console import Console
from rich.table import Table

from subdomain_enum import SubdomainEnumerator

console = Console()


# ────────────────────────────────────────────────────────────────────────────
# Banner
# ────────────────────────────────────────────────────────────────────────────
def banner():
    console.print(
        r"""
[bold cyan]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

        ReconX Subdomains
        Advanced Enumeration Engine
[/bold cyan]
"""
    )


# ────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ────────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconx-subdomains",
        description=(
            "Advanced subdomain enumeration engine for "
            "offensive security and reconnaissance workflows."
        ),
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Target domain",
    )

    parser.add_argument(
        "-b",
        "--bruteforce",
        action="store_true",
        help="Enable DNS bruteforce",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="DNS bruteforce wordlist",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=30,
        help="Thread count (default: 30)",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export JSON output",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--vt-key",
        help="VirusTotal API key",
    )

    parser.add_argument(
        "--github-key",
        help="GitHub API token",
    )

    return parser.parse_args()


# ────────────────────────────────────────────────────────────────────────────
# Validation
# ────────────────────────────────────────────────────────────────────────────
def validate_args(args):
    if args.bruteforce and not args.wordlist:
        console.print(
            "[red]DNS bruteforce requires a wordlist.[/red]"
        )

        console.print(
            "[yellow]Example:[/yellow] "
            "-b -w dns.txt"
        )

        sys.exit(1)

    if args.wordlist:
        wordlist = Path(args.wordlist)

        if not wordlist.exists():
            console.print(
                f"[red]Wordlist not found:[/red] {wordlist}"
            )

            sys.exit(1)

    if args.threads <= 0:
        console.print(
            "[red]Thread count must be greater than 0.[/red]"
        )

        sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Output Helpers
# ────────────────────────────────────────────────────────────────────────────
def save_json(results, output_path):
    data = {
        "count": len(results),
        "subdomains": sorted(results),
        "timestamp": int(time.time()),
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)

    console.print(
        f"[green][+][/green] JSON saved → {output_path}"
    )


def save_text(results, output_path):
    with open(output_path, "w") as f:
        f.write("\n".join(sorted(results)))

    console.print(
        f"[green][+][/green] Output saved → {output_path}"
    )


def print_summary(results, elapsed):
    console.print()

    table = Table(title="Enumeration Summary")

    table.add_column(
        "Metric",
        style="cyan",
    )

    table.add_column(
        "Value",
        style="green",
    )

    table.add_row(
        "Total Subdomains",
        str(len(results)),
    )

    table.add_row(
        "Execution Time",
        f"{elapsed:.2f}s",
    )

    console.print(table)


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    validate_args(args)

    banner()

    api_keys = {
        "virustotal": args.vt_key,
        "github": args.github_key,
    }

    start = time.time()

    try:
        enum = SubdomainEnumerator(
            domain=args.domain,
            threads=args.threads,
            verbose=args.verbose,
            api_keys=api_keys,
        )

        results = enum.run(
            bruteforce=args.bruteforce,
            dns_wordlist=args.wordlist,
            output_file=(
                args.output
                if args.output and not args.json
                else None
            ),
        )

        elapsed = time.time() - start

        # ────────────────────────────────────────────────────────────────
        # Print Results
        # ────────────────────────────────────────────────────────────────
        console.print()

        for subdomain in sorted(results):
            console.print(
                f"[green]{subdomain}[/green]"
            )

        # ────────────────────────────────────────────────────────────────
        # Save JSON
        # ────────────────────────────────────────────────────────────────
        if args.json:
            output_file = (
                args.output
                or f"{args.domain}_subdomains.json"
            )

            save_json(
                results,
                output_file,
            )

        # ────────────────────────────────────────────────────────────────
        # Save TXT
        # ────────────────────────────────────────────────────────────────
        elif args.output:
            save_text(
                results,
                args.output,
            )

        # ────────────────────────────────────────────────────────────────
        # Summary
        # ────────────────────────────────────────────────────────────────
        print_summary(
            results,
            elapsed,
        )

    except KeyboardInterrupt:
        console.print(
            "\n[red]Interrupted by user[/red]"
        )

        sys.exit(1)

    except Exception as e:
        console.print(
            f"\n[red]Fatal Error:[/red] {e}"
        )

        if args.verbose:
            raise

        sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()#!/usr/bin/env python3

"""
ReconX Subdomains - CLI Interface

Command-line interface for:
- subdomain enumeration
- DNS bruteforce
- validation workflows
- reconnaissance automation
"""

import argparse
import json
import sys
import time

from pathlib import Path

from rich.console import Console
from rich.table import Table

from subdomain_enum import SubdomainEnumerator

console = Console()


# ────────────────────────────────────────────────────────────────────────────
# Banner
# ────────────────────────────────────────────────────────────────────────────
def banner():
    console.print(
        r"""
[bold cyan]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

        ReconX Subdomains
        Advanced Enumeration Engine
[/bold cyan]
"""
    )


# ────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ────────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconx-subdomains",
        description=(
            "Advanced subdomain enumeration engine for "
            "offensive security and reconnaissance workflows."
        ),
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Target domain",
    )

    parser.add_argument(
        "-b",
        "--bruteforce",
        action="store_true",
        help="Enable DNS bruteforce",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="DNS bruteforce wordlist",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=30,
        help="Thread count (default: 30)",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export JSON output",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--vt-key",
        help="VirusTotal API key",
    )

    parser.add_argument(
        "--github-key",
        help="GitHub API token",
    )

    return parser.parse_args()


# ────────────────────────────────────────────────────────────────────────────
# Output Helpers
# ────────────────────────────────────────────────────────────────────────────
def save_json(results, output_path):
    data = {
        "count": len(results),
        "subdomains": sorted(results),
        "timestamp": int(time.time()),
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)

    console.print(
        f"[green][+][/green] JSON saved → {output_path}"
    )


def save_text(results, output_path):
    with open(output_path, "w") as f:
        f.write("\n".join(sorted(results)))

    console.print(
        f"[green][+][/green] Output saved → {output_path}"
    )


def print_summary(results, elapsed):
    console.print()

    table = Table(title="Enumeration Summary")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "Total Subdomains",
        str(len(results))
    )

    table.add_row(
        "Execution Time",
        f"{elapsed:.2f}s"
    )

    console.print(table)


# ────────────────────────────────────────────────────────────────────────────
# Validation
# ────────────────────────────────────────────────────────────────────────────
def validate_args(args):
    if args.bruteforce and not args.wordlist:
        console.print(
            "[red]DNS bruteforce requires a wordlist.[/red]"
        )

        console.print(
            "[yellow]Use:[/yellow] "
            "-b -w wordlist.txt"
        )

        sys.exit(1)

    if args.wordlist:
        wordlist = Path(args.wordlist)

        if not wordlist.exists():
            console.print(
                f"[red]Wordlist not found:[/red] {wordlist}"
            )

            sys.exit(1)

    if args.threads <= 0:
        console.print(
            "[red]Thread count must be greater than 0.[/red]"
        )

        sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    validate_args(args)

    banner()

    api_keys = {
        "virustotal": args.vt_key,
        "github": args.github_key,
    }

    start = time.time()

    try:
        enum = SubdomainEnumerator(
            domain=args.domain,
            threads=args.threads,
            verbose=args.verbose,
            api_keys=api_keys,
        )

        results = enum.run(
            bruteforce=args.bruteforce,
            dns_wordlist=args.wordlist,
            output_file=(
                args.output
                if args.output and not args.json
                else None
            ),
        )

        elapsed = time.time() - start

        # ────────────────────────────────────────────────────────────────
        # Print Results
        # ────────────────────────────────────────────────────────────────
        console.print()

        for subdomain in sorted(results):
            console.print(
                f"[green]{subdomain}[/green]"
            )

        # ────────────────────────────────────────────────────────────────
        # Save JSON
        # ────────────────────────────────────────────────────────────────
        if args.json:
            output_file = (
                args.output
                or f"{args.domain}_subdomains.json"
            )

            save_json(results, output_file)

        # ────────────────────────────────────────────────────────────────
        # Save TXT
        # ────────────────────────────────────────────────────────────────
        elif args.output:
            save_text(results, args.output)

        # ────────────────────────────────────────────────────────────────
        # Summary
        # ────────────────────────────────────────────────────────────────
        print_summary(results, elapsed)

    except KeyboardInterrupt:
        console.print(
            "\n[red]Interrupted by user[/red]"
        )

        sys.exit(1)

    except Exception as e:
        console.print(
            f"\n[red]Fatal Error:[/red] {e}"
        )

        if args.verbose:
            raise

        sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
