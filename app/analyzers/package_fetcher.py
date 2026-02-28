"""
Package Fetcher — Download and extract source code from various sources.

Supports:
- /plugin install <name>@<marketplace>  →  GitHub marketplace
- /plugin add <org/repo>               →  GitHub repository
- /plugin add /path/to/skill           →  Local folder
- pip install <package>                →  Fetch from PyPI
- npm install <package>                →  Fetch from npm registry
- <org/repo>                           →  GitHub repository shorthand
- git clone <url>                      →  Git repository
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Max file size to analyze per file (100KB)
MAX_FILE_SIZE = 100_000
# Max total source size (500KB)
MAX_TOTAL_SIZE = 500_000
# File extensions to analyze
ANALYZABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
}
# Files to always check (regardless of extension)
IMPORTANT_FILES = {
    "setup.py", "setup.cfg", "pyproject.toml", "package.json",
    "Makefile", "Dockerfile", ".env", "requirements.txt",
    "SKILL.md", "skill.json", "skill.yaml", "manifest.json",
}


class PackageFetchResult:
    """Result of fetching a package."""

    def __init__(self):
        self.package_name: str = ""
        self.version: str = ""
        self.source: str = ""           # "pypi" | "npm" | "github" | "local"
        self.files: dict[str, str] = {} # {relative_path: content}
        self.metadata: dict = {}
        self.error: Optional[str] = None

    @property
    def combined_source(self) -> str:
        """Combine all files into a single annotated source string."""
        parts = []
        for path, content in sorted(self.files.items()):
            parts.append(f"# ===== FILE: {path} =====\n{content}\n")
        return "\n".join(parts)

    @property
    def total_size(self) -> int:
        return sum(len(c) for c in self.files.values())


async def fetch_package(command: str) -> PackageFetchResult:
    """
    Parse an install command and fetch the package source code.

    Supported formats:
        /plugin install <name>@<marketplace>
        /plugin install <name>+@<marketplace>
        /plugin add <org/repo>
        /plugin add /local/path
        pip install <package>
        npm install <package>
        <org>/<repo>  (GitHub shorthand)
        git clone <url>
    """
    command = command.strip()
    result = PackageFetchResult()

    try:
        if _is_plugin_command(command):
            await _handle_plugin_command(command, result)

        elif _is_pip_command(command):
            pkg_name, version = _parse_pip_command(command)
            result.package_name = pkg_name
            result.version = version or "latest"
            result.source = "pypi"
            await _fetch_from_pypi(pkg_name, version, result)

        elif _is_npm_command(command):
            pkg_name, version = _parse_npm_command(command)
            result.package_name = pkg_name
            result.version = version or "latest"
            result.source = "npm"
            await _fetch_from_npm(pkg_name, version, result)

        elif _is_git_command(command):
            url = _parse_git_command(command)
            result.package_name = url.rstrip("/").split("/")[-1].replace(".git", "")
            result.source = "github"
            await _fetch_from_github_url(url, result)

        elif _is_github_url(command):
            result.source = "github"
            await _fetch_from_github_url(command, result)

        elif _is_github_shorthand(command):
            # e.g. "anthropics/skills" or "owner/repo"
            org, repo = command.split("/", 1)
            result.package_name = repo
            result.source = "github"
            await _fetch_from_github(org, repo, result)

        elif _is_local_path(command):
            await _fetch_from_local(command, result)

        else:
            # Fallback: try as PyPI package name
            result.package_name = command.split()[0] if command.split() else command
            result.source = "pypi"
            result.version = "latest"
            await _fetch_from_pypi(result.package_name, None, result)

    except Exception as e:
        result.error = str(e)
        logger.error(f"Failed to fetch package: {e}")

    return result


# ---------------------------------------------------------------------------
# Command detection
# ---------------------------------------------------------------------------

def _is_plugin_command(cmd: str) -> bool:
    return bool(re.match(r"^/?plugin\s+(install|add|marketplace)\s+", cmd, re.I))

def _is_pip_command(cmd: str) -> bool:
    return bool(re.match(r"^(pip3?|python\s+-m\s+pip)\s+install\s+", cmd, re.I))

def _is_npm_command(cmd: str) -> bool:
    return bool(re.match(r"^(npm|yarn|pnpm)\s+(install|add)\s+", cmd, re.I))

def _is_git_command(cmd: str) -> bool:
    return bool(re.match(r"^git\s+clone\s+", cmd, re.I))

def _is_github_url(cmd: str) -> bool:
    return bool(re.match(r"^https?://github\.com/", cmd, re.I))

def _is_github_shorthand(cmd: str) -> bool:
    """Match 'org/repo' pattern (no spaces, exactly one slash)."""
    return bool(re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", cmd.strip()))

def _is_local_path(cmd: str) -> bool:
    """Check if the command looks like a local path."""
    cmd = cmd.strip()
    return (
        cmd.startswith("/") or
        cmd.startswith("./") or
        cmd.startswith("..") or
        cmd.startswith("~") or
        (len(cmd) > 2 and cmd[1] == ":" and cmd[2] in "/\\")  # Windows drive
    )


def _parse_pip_command(cmd: str) -> tuple[str, Optional[str]]:
    """Extract package name and optional version from pip install command."""
    rest = re.sub(r"^(pip3?|python\s+-m\s+pip)\s+install\s+", "", cmd, flags=re.I).strip()
    rest = re.sub(r"-[a-zA-Z-]+\s+\S+", "", rest).strip()
    rest = re.sub(r"--\S+", "", rest).strip()
    match = re.match(r"^([a-zA-Z0-9_.-]+)(?:[=<>!~]+(.+))?$", rest)
    if match:
        return match.group(1), match.group(2)
    return rest, None


def _parse_npm_command(cmd: str) -> tuple[str, Optional[str]]:
    """Extract package name and optional version from npm install command."""
    rest = re.sub(r"^(npm|yarn|pnpm)\s+(install|add)\s+", "", cmd, flags=re.I).strip()
    rest = re.sub(r"--\S+", "", rest).strip()
    rest = re.sub(r"-[DSgOE]", "", rest).strip()
    match = re.match(r"^((?:@[\w.-]+/)?[\w.-]+)(?:@(.+))?$", rest)
    if match:
        return match.group(1), match.group(2)
    return rest, None


def _parse_git_command(cmd: str) -> str:
    """Extract URL from git clone command."""
    rest = re.sub(r"^git\s+clone\s+", "", cmd, flags=re.I).strip()
    return rest.split()[0]


# ---------------------------------------------------------------------------
# Plugin command handler
# ---------------------------------------------------------------------------

async def _handle_plugin_command(cmd: str, result: PackageFetchResult):
    """
    Handle /plugin install/add/marketplace commands.
    
    Formats:
        /plugin marketplace add anthropics/skills
        /plugin install document-skills+@anthropic-agent-skills
        /plugin install example-skills@marketplace-name
        /plugin add /path/to/your-skill-folder
        /plugin add org/repo
    """
    # Remove leading /
    cmd = cmd.lstrip("/").strip()
    # Remove "plugin" prefix and the action verb
    rest = re.sub(r"^plugin\s+(install|add|marketplace\s+add)\s+", "", cmd, flags=re.I).strip()
    # Remove trailing comments
    rest = re.sub(r"#.*$", "", rest).strip()

    if not rest:
        result.error = "No package specified in plugin command"
        return

    # Check if it's a local path
    if _is_local_path(rest):
        await _fetch_from_local(rest, result)
        return

    # Parse "name@marketplace" or "name+@marketplace" format
    at_match = re.match(r"^([\w._+-]+)\+?@([\w._-]+)$", rest)
    if at_match:
        skill_name = at_match.group(1).rstrip("+")
        marketplace = at_match.group(2)
        result.package_name = skill_name
        result.source = "github"
        result.metadata["marketplace"] = marketplace
        # Map to GitHub: marketplace org / skill-name or marketplace as org
        await _fetch_from_github(marketplace, skill_name, result)
        return

    # Check if it's org/repo format
    if _is_github_shorthand(rest):
        org, repo = rest.split("/", 1)
        result.package_name = repo
        result.source = "github"
        await _fetch_from_github(org, repo, result)
        return

    # Check if it's a GitHub URL
    if _is_github_url(rest):
        result.source = "github"
        await _fetch_from_github_url(rest, result)
        return

    # Fallback: treat as a skill/package name, try GitHub search
    result.package_name = rest
    result.source = "github"
    result.error = (
        f"Could not resolve '{rest}'. Try using one of these formats:\n"
        f"  - org/repo (e.g. anthropics/skills)\n"
        f"  - /plugin install name@marketplace\n"
        f"  - /plugin add /local/path"
    )


# ---------------------------------------------------------------------------
# GitHub fetcher
# ---------------------------------------------------------------------------

async def _fetch_from_github(org: str, repo: str, result: PackageFetchResult):
    """Fetch source from a GitHub repository (default branch zipball)."""
    result.package_name = result.package_name or repo
    api_url = f"https://api.github.com/repos/{org}/{repo}"

    async with httpx.AsyncClient(timeout=30) as client:
        # Get repo metadata
        resp = await client.get(api_url)
        if resp.status_code == 404:
            result.error = f"GitHub repository '{org}/{repo}' not found"
            return
        resp.raise_for_status()

        repo_data = resp.json()
        default_branch = repo_data.get("default_branch", "main")
        result.version = default_branch
        result.metadata = {
            "name": repo_data.get("full_name"),
            "description": repo_data.get("description"),
            "stars": repo_data.get("stargazers_count"),
            "license": (repo_data.get("license") or {}).get("spdx_id"),
            "url": repo_data.get("html_url"),
            "default_branch": default_branch,
        }

        # Download zipball
        zip_url = f"https://api.github.com/repos/{org}/{repo}/zipball/{default_branch}"
        logger.info(f"Downloading {org}/{repo} from GitHub...")
        resp = await client.get(zip_url, follow_redirects=True)
        resp.raise_for_status()

        _extract_archive(resp.content, "archive.zip", result)


async def _fetch_from_github_url(url: str, result: PackageFetchResult):
    """
    Parse a GitHub URL and fetch source. Supports:
    - https://github.com/org/repo
    - https://github.com/org/repo/tree/branch/path/to/dir
    - https://github.com/org/repo/blob/branch/path/to/file
    """
    url = url.rstrip("/").replace(".git", "")

    # Check for blob URL (single file)
    blob_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)", url
    )
    if blob_match:
        org, repo, branch, filepath = blob_match.groups()
        result.package_name = result.package_name or filepath.split("/")[-1].split(".")[0]
        result.source = "github"
        result.version = branch
        raw_url = f"https://raw.githubusercontent.com/{org}/{repo}/{branch}/{filepath}"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(raw_url)
            if resp.status_code == 404:
                result.error = f"File not found: {filepath}"
                return
            resp.raise_for_status()
            result.files[filepath.split("/")[-1]] = resp.text
            result.metadata = {
                "name": f"{org}/{repo}",
                "url": url,
                "file": filepath,
                "default_branch": branch,
            }
        return

    # Check for tree URL (subdirectory)
    tree_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.*)", url
    )
    if tree_match:
        org, repo, branch, subpath = tree_match.groups()
        result.package_name = result.package_name or subpath.rstrip("/").split("/")[-1]
        result.source = "github"
        result.version = branch
        result.metadata = {
            "name": f"{org}/{repo}",
            "url": url,
            "subdirectory": subpath,
            "default_branch": branch,
        }
        await _fetch_github_subtree(org, repo, branch, subpath, result)
        return

    # Plain repo URL
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if not match:
        result.error = f"Invalid GitHub URL: {url}"
        return
    org, repo = match.group(1), match.group(2)
    result.package_name = result.package_name or repo
    await _fetch_from_github(org, repo, result)


async def _fetch_github_subtree(
    org: str, repo: str, branch: str, subpath: str,
    result: PackageFetchResult,
):
    """Fetch only files within a specific subdirectory of a GitHub repo."""
    api_url = (
        f"https://api.github.com/repos/{org}/{repo}"
        f"/git/trees/{branch}?recursive=1"
    )
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(api_url)
        if resp.status_code != 200:
            # Fallback to full repo zip
            await _fetch_from_github(org, repo, result)
            return

        tree_data = resp.json()
        subpath = subpath.rstrip("/")
        total_collected = 0

        for item in tree_data.get("tree", []):
            if item["type"] != "blob":
                continue
            path = item["path"]
            if not path.startswith(subpath + "/"):
                continue
            rel_path = path[len(subpath) + 1:]
            size = item.get("size", 0)

            if total_collected >= MAX_TOTAL_SIZE:
                break
            if not _should_analyze(rel_path, size):
                continue

            # Fetch file content
            raw_url = (
                f"https://raw.githubusercontent.com"
                f"/{org}/{repo}/{branch}/{path}"
            )
            try:
                file_resp = await client.get(raw_url)
                if file_resp.status_code == 200:
                    result.files[rel_path] = file_resp.text
                    total_collected += len(file_resp.text)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Local path fetcher
# ---------------------------------------------------------------------------

async def _fetch_from_local(path_str: str, result: PackageFetchResult):
    """Read source files from a local directory or file."""
    # Expand ~ and resolve
    path = Path(os.path.expanduser(path_str)).resolve()
    result.source = "local"

    if not path.exists():
        result.error = f"Path not found: {path}"
        return

    if path.is_file():
        result.package_name = path.stem
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            if len(content) <= MAX_FILE_SIZE:
                result.files[path.name] = content
        except Exception as e:
            result.error = f"Failed to read file: {e}"
        return

    # Directory
    result.package_name = path.name
    result.metadata = {"path": str(path)}
    total_collected = 0

    for root, dirs, files in os.walk(path):
        # Skip hidden dirs and common non-source directories
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in {
                "node_modules", "__pycache__", ".git", "venv", ".venv", "dist", "build"
            }
        ]
        for fname in files:
            if total_collected >= MAX_TOTAL_SIZE:
                break
            fpath = Path(root) / fname
            size = fpath.stat().st_size
            if _should_analyze(fname, size):
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    rel_path = str(fpath.relative_to(path)).replace("\\", "/")
                    result.files[rel_path] = content
                    total_collected += len(content)
                except Exception:
                    pass

async def _fetch_from_pypi(
    package_name: str,
    version: Optional[str],
    result: PackageFetchResult,
):
    """Fetch package source from PyPI."""
    async with httpx.AsyncClient(timeout=30) as client:
        # Get package metadata
        url = f"https://pypi.org/pypi/{package_name}/json"
        if version:
            url = f"https://pypi.org/pypi/{package_name}/{version}/json"

        resp = await client.get(url)
        if resp.status_code == 404:
            result.error = f"Package '{package_name}' not found on PyPI"
            return
        resp.raise_for_status()

        data = resp.json()
        result.version = data["info"]["version"]
        result.metadata = {
            "name": data["info"]["name"],
            "version": data["info"]["version"],
            "summary": data["info"]["summary"],
            "author": data["info"]["author"],
            "license": data["info"]["license"],
            "home_page": data["info"]["home_page"],
            "project_url": data["info"]["project_url"],
        }

        # Find the source distribution (sdist) or wheel
        urls = data.get("urls", [])
        sdist_url = None
        wheel_url = None

        for u in urls:
            if u["packagetype"] == "sdist":
                sdist_url = u["url"]
            elif u["packagetype"] == "bdist_wheel":
                wheel_url = u["url"]

        download_url = sdist_url or wheel_url
        if not download_url:
            result.error = f"No downloadable source found for '{package_name}'"
            return

        # Download and extract
        logger.info(f"Downloading {package_name} from {download_url}")
        resp = await client.get(download_url, follow_redirects=True)
        resp.raise_for_status()

        _extract_archive(resp.content, download_url, result)


# ---------------------------------------------------------------------------
# npm fetcher
# ---------------------------------------------------------------------------

async def _fetch_from_npm(
    package_name: str,
    version: Optional[str],
    result: PackageFetchResult,
):
    """Fetch package source from npm registry."""
    async with httpx.AsyncClient(timeout=30) as client:
        # Get package metadata
        resp = await client.get(f"https://registry.npmjs.org/{package_name}")
        if resp.status_code == 404:
            result.error = f"Package '{package_name}' not found on npm"
            return
        resp.raise_for_status()

        data = resp.json()
        versions = data.get("versions", {})

        if not version or version == "latest":
            version = data.get("dist-tags", {}).get("latest")
        
        if version not in versions:
            result.error = f"Version '{version}' not found for '{package_name}'"
            return

        version_data = versions[version]
        result.version = version
        result.metadata = {
            "name": version_data.get("name"),
            "version": version,
            "description": version_data.get("description"),
            "author": str(version_data.get("author", "")),
            "license": version_data.get("license"),
            "homepage": version_data.get("homepage"),
        }

        tarball_url = version_data.get("dist", {}).get("tarball")
        if not tarball_url:
            result.error = f"No tarball URL found for '{package_name}@{version}'"
            return

        # Download and extract
        logger.info(f"Downloading {package_name}@{version} from {tarball_url}")
        resp = await client.get(tarball_url, follow_redirects=True)
        resp.raise_for_status()

        _extract_archive(resp.content, tarball_url, result)


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

def _extract_archive(data: bytes, url: str, result: PackageFetchResult):
    """Extract source files from a tar.gz or zip/wheel archive."""
    total_collected = 0

    try:
        if url.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    if total_collected >= MAX_TOTAL_SIZE:
                        break
                    if _should_analyze(member.name, member.size):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            try:
                                text = content.decode("utf-8", errors="replace")
                                # Normalize the path (remove the top-level dir)
                                parts = member.name.split("/", 1)
                                rel_path = parts[1] if len(parts) > 1 else parts[0]
                                result.files[rel_path] = text
                                total_collected += len(text)
                            except Exception:
                                pass

        elif url.endswith((".zip", ".whl")):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if total_collected >= MAX_TOTAL_SIZE:
                        break
                    if _should_analyze(info.filename, info.file_size):
                        try:
                            content = zf.read(info.filename)
                            text = content.decode("utf-8", errors="replace")
                            result.files[info.filename] = text
                            total_collected += len(text)
                        except Exception:
                            pass

        else:
            # Try tar.gz first, then zip
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if not member.isfile():
                            continue
                        if total_collected >= MAX_TOTAL_SIZE:
                            break
                        if _should_analyze(member.name, member.size):
                            f = tar.extractfile(member)
                            if f:
                                content = f.read()
                                try:
                                    text = content.decode("utf-8", errors="replace")
                                    parts = member.name.split("/", 1)
                                    rel_path = parts[1] if len(parts) > 1 else parts[0]
                                    result.files[rel_path] = text
                                    total_collected += len(text)
                                except Exception:
                                    pass
            except tarfile.TarError:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        if total_collected >= MAX_TOTAL_SIZE:
                            break
                        if _should_analyze(info.filename, info.file_size):
                            try:
                                content = zf.read(info.filename)
                                text = content.decode("utf-8", errors="replace")
                                result.files[info.filename] = text
                                total_collected += len(text)
                            except Exception:
                                pass

    except Exception as e:
        result.error = f"Failed to extract archive: {e}"
        logger.error(f"Archive extraction error: {e}")

    if not result.files:
        result.error = result.error or "No analyzable source files found in package"


def _should_analyze(filename: str, size: int) -> bool:
    """Check if a file should be analyzed."""
    if size > MAX_FILE_SIZE or size == 0:
        return False
    basename = os.path.basename(filename)
    if basename in IMPORTANT_FILES:
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in ANALYZABLE_EXTENSIONS
