"""
ReconX Subdomains - Tool Discovery Utilities

Cross-platform binary discovery helpers for reconnaissance tooling.

Features:
- automatic PATH discovery
- Go binary path injection
- fallback binary resolution
- subprocess-safe environment generation
- optional tool status inspection
"""

import os
import shutil

from pathlib import Path
from typing import Dict, Optional


# ────────────────────────────────────────────────────────────────────────────
# Common Binary Locations
# ────────────────────────────────────────────────────────────────────────────
FALLBACK_PATHS = [
    os.path.expanduser("~/go/bin"),
    "/usr/local/go/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/go/bin",
    "/root/go/bin",
]


# ────────────────────────────────────────────────────────────────────────────
# Dynamically Include /home/*/go/bin
# ────────────────────────────────────────────────────────────────────────────
try:
    for path in Path("/home").glob("*/go/bin"):
        path_str = str(path)

        if path_str not in FALLBACK_PATHS:
            FALLBACK_PATHS.append(path_str)

except (PermissionError, OSError):
    pass


# ────────────────────────────────────────────────────────────────────────────
# Supported Recon Tooling
# ────────────────────────────────────────────────────────────────────────────
KNOWN_TOOLS = {
    "alterx",
    "amass",
    "anew",
    "arjun",
    "assetfinder",
    "dig",
    "dnsx",
    "ffuf",
    "gau",
    "gf",
    "gowitness",
    "hakrawler",
    "httpx",
    "httprobe",
    "interactsh-client",
    "katana",
    "kerbrute",
    "masscan",
    "naabu",
    "nikto",
    "nmap",
    "nuclei",
    "qsreplace",
    "shuffledns",
    "subfinder",
    "unfurl",
    "waybackurls",
    "whatweb",
}


# ────────────────────────────────────────────────────────────────────────────
# Environment Builder
# ────────────────────────────────────────────────────────────────────────────
def get_env() -> Dict[str, str]:
    """
    Build a subprocess-safe environment with common Go paths injected into PATH.
    """

    env = os.environ.copy()

    existing_path = env.get("PATH", "")

    valid_dirs = []

    for directory in FALLBACK_PATHS:
        try:
            path = Path(directory)

            if path.is_dir():
                valid_dirs.append(str(path))

        except (PermissionError, OSError):
            continue

    # Remove duplicates while preserving order
    valid_dirs = list(dict.fromkeys(valid_dirs))

    env["PATH"] = ":".join(valid_dirs) + (
        ":" + existing_path if existing_path else ""
    )

    return env


# ────────────────────────────────────────────────────────────────────────────
# Binary Discovery
# ────────────────────────────────────────────────────────────────────────────
def find_tool(name: str) -> Optional[str]:
    """
    Locate a binary by searching:
        1. system PATH
        2. fallback binary locations

    Returns:
        str: absolute binary path
        None: if not found
    """

    # Check system PATH first
    found = shutil.which(name)

    if found:
        return found

    # Check fallback locations
    for base in FALLBACK_PATHS:
        try:
            path = Path(base) / name

            if (
                path.exists()
                and path.is_file()
                and os.access(path, os.X_OK)
            ):
                return str(path)

        except (PermissionError, OSError):
            continue

    return None


# ────────────────────────────────────────────────────────────────────────────
# Tool Availability Inspection
# ────────────────────────────────────────────────────────────────────────────
def tool_status() -> Dict[str, Optional[str]]:
    """
    Return:
        {
            "tool_name": "/resolved/path" | None
        }
    """

    return {
        tool: find_tool(tool)
        for tool in sorted(KNOWN_TOOLS)
    }


# ────────────────────────────────────────────────────────────────────────────
# Shared Subprocess Environment
# ────────────────────────────────────────────────────────────────────────────
ENV = get_env()


# ────────────────────────────────────────────────────────────────────────────
# Standalone Testing
# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n[ ReconX Tool Discovery ]\n")

    status = tool_status()

    for tool, path in status.items():
        print(f"{tool:<20} -> {path}")
