"""
core/scanner.py
GitHub API integration and scanning orchestrator.

Fetches repository files, runs all regex patterns + entropy analysis,
filters false positives, and returns structured findings.
"""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from core.entropy import analyse_file_content, EntropyFinding
from core.patterns import (
    ALL_PATTERNS,
    SENSITIVE_EXTENSIONS,
    SENSITIVE_FILENAMES,
    SecretPattern,
)
from core.validator import extract_match_value, is_false_positive, mask_secret

logger = logging.getLogger(__name__)

GITHUB_API   = "https://api.github.com"
MAX_FILE_SIZE = 1_000_000   # 1 MB — skip binary/huge files
MAX_REPOS     = 10          # max repos when scanning a user
MAX_FILES     = 300         # max files per repo to avoid timeout
CONCURRENCY   = 5           # parallel file fetch limit


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    file_path:    str
    line_number:  Optional[int]
    secret_type:  str
    severity:     str
    matched_value: str          # masked
    raw_line:     str = ""      # the surrounding line (for context in report)


@dataclass
class ScanResult:
    target:       str
    scan_type:    str           # repo | user | env
    findings:     list[Finding] = field(default_factory=list)
    total_files:  int = 0
    duration:     float = 0.0
    errors:       list[str] = field(default_factory=list)

    # Counts (computed from findings)
    @property
    def total_leaks(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")


# ─────────────────────────────────────────────────────────────────────────────
# GITHUB CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token   = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "LeakHunterBot/1.0",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def _get(self, session: aiohttp.ClientSession, url: str) -> Optional[dict | list]:
        try:
            async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 404:
                    return None
                if resp.status == 403:
                    raise PermissionError("GitHub API rate limit exceeded or access denied")
                if resp.status == 401:
                    raise PermissionError("Invalid GitHub token")
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as e:
            logger.warning("GitHub API request failed: %s — %s", url, e)
            return None

    async def get_repo_info(self, session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[dict]:
        return await self._get(session, f"{GITHUB_API}/repos/{owner}/{repo}")

    async def get_user_repos(self, session: aiohttp.ClientSession, username: str) -> list[dict]:
        url  = f"{GITHUB_API}/users/{username}/repos?per_page=100&sort=updated&type=public"
        data = await self._get(session, url)
        return data[:MAX_REPOS] if isinstance(data, list) else []

    async def get_tree(self, session: aiohttp.ClientSession, owner: str, repo: str, branch: str) -> list[dict]:
        url  = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        data = await self._get(session, url)
        if not data or "tree" not in data:
            return []
        return [
            item for item in data["tree"]
            if item.get("type") == "blob" and item.get("size", 0) <= MAX_FILE_SIZE
        ]

    async def get_file_content(self, session: aiohttp.ClientSession, owner: str, repo: str, path: str) -> Optional[str]:
        url  = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
        data = await self._get(session, url)
        if not data or not isinstance(data, dict):
            return None
        content  = data.get("content", "")
        encoding = data.get("encoding", "")
        if encoding == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="replace")
            except Exception:
                return None
        return content or None

    async def verify_token(self, token: str) -> bool:
        """Test whether a GitHub PAT is valid."""
        headers = {**self.headers, "Authorization": f"Bearer {token}"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{GITHUB_API}/user",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_repo_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL or 'owner/repo' string."""
    url = url.strip().rstrip("/")
    if "github.com" in url:
        parsed = urlparse(url)
        parts  = parsed.path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")
    elif "/" in url:
        parts = url.split("/")
        return parts[0], parts[1]
    raise ValueError(f"Cannot parse repository: {url!r}")


def _is_sensitive_file(path: str) -> bool:
    """Return True if the file should be prioritised for scanning."""
    filename = path.split("/")[-1].lower()
    ext      = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    return filename in SENSITIVE_FILENAMES or ext in SENSITIVE_EXTENSIONS


def _is_scannable_extension(path: str) -> bool:
    """Skip binary-like file extensions."""
    BINARY_EXT = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".exe", ".bin", ".dll", ".so", ".dylib", ".wasm",
        ".mp3", ".mp4", ".avi", ".mov", ".wav",
        ".ttf", ".woff", ".woff2", ".eot", ".otf",
        ".lock",  # package-lock.json, yarn.lock — too noisy
    }
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext not in BINARY_EXT


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _scan_content(content: str, file_path: str, env_only: bool = False) -> list[Finding]:
    """
    Run all patterns + entropy analysis over file content.
    Returns a deduplicated list of Findings.
    """
    findings: list[Finding] = []
    seen_keys: set[tuple[str, int]] = set()   # (secret_type, line_number)

    lines = content.splitlines()

    for pattern in ALL_PATTERNS:
        for match in pattern.regex.finditer(content):
            raw_value = extract_match_value(match)

            # False-positive filter
            if is_false_positive(raw_value, file_path):
                continue

            # Find the line number
            line_number = content[: match.start()].count("\n") + 1
            raw_line    = lines[line_number - 1].strip()[:200] if lines else ""

            dedup_key = (pattern.name, line_number)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=pattern.name,
                    severity=pattern.severity,
                    matched_value=mask_secret(raw_value),
                    raw_line=raw_line,
                )
            )

    # Run entropy analysis (skip for env-only mode to keep reports clean)
    if not env_only:
        entropy_hits = analyse_file_content(content)
        for hit in entropy_hits:
            dedup_key = ("Suspicious High-Entropy String", hit.line_number)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=hit.line_number,
                        secret_type="Suspicious High-Entropy String",
                        severity="LOW",
                        matched_value=mask_secret(hit.value),
                        raw_line=hit.context,
                    )
                )

    return findings


async def _fetch_and_scan(
    session:    aiohttp.ClientSession,
    client:     GitHubClient,
    owner:      str,
    repo:       str,
    file_item:  dict,
    sem:        asyncio.Semaphore,
    env_only:   bool = False,
) -> list[Finding]:
    """Fetch a single file and scan it."""
    async with sem:
        path    = file_item["path"]
        content = await client.get_file_content(session, owner, repo, path)
        if content is None:
            return []
        if env_only and not (_is_sensitive_file(path)):
            return []
        return _scan_content(content, path, env_only=env_only)


async def _scan_single_repo(
    client:   GitHubClient,
    owner:    str,
    repo:     str,
    env_only: bool = False,
) -> tuple[list[Finding], int]:
    """
    Scan one repository. Returns (findings, files_scanned).
    """
    async with aiohttp.ClientSession() as session:
        # Get default branch
        repo_info = await client.get_repo_info(session, owner, repo)
        if not repo_info:
            raise ValueError(f"Repository '{owner}/{repo}' not found or inaccessible")

        default_branch = repo_info.get("default_branch", "main")
        tree           = await client.get_tree(session, owner, repo, default_branch)

        if not tree:
            return [], 0

        # Filter to scannable files
        if env_only:
            files = [
                item for item in tree
                if _is_sensitive_file(item["path"])
            ]
        else:
            files = [
                item for item in tree
                if _is_scannable_extension(item["path"])
            ][:MAX_FILES]

        # Prioritise sensitive files first
        files.sort(key=lambda x: (0 if _is_sensitive_file(x["path"]) else 1, x["path"]))

        sem      = asyncio.Semaphore(CONCURRENCY)
        tasks    = [
            _fetch_and_scan(session, client, owner, repo, f, sem, env_only)
            for f in files
        ]
        results  = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning("File scan error: %s", result)

        return all_findings, len(files)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

async def scan_repo(
    repo_url:  str,
    token:     Optional[str] = None,
    env_only:  bool = False,
) -> ScanResult:
    """Scan a single repository for leaked secrets."""
    start  = time.monotonic()
    client = GitHubClient(token)

    try:
        owner, repo = _parse_repo_url(repo_url)
    except ValueError as e:
        return ScanResult(
            target=repo_url,
            scan_type="env" if env_only else "repo",
            errors=[str(e)],
        )

    scan_type = "env" if env_only else "repo"
    result    = ScanResult(target=f"github.com/{owner}/{repo}", scan_type=scan_type)

    try:
        findings, files_scanned = await _scan_single_repo(client, owner, repo, env_only)
        result.findings    = findings
        result.total_files = files_scanned
    except PermissionError as e:
        result.errors.append(str(e))
    except Exception as e:
        logger.exception("Unexpected error scanning %s/%s", owner, repo)
        result.errors.append(f"Unexpected error: {e}")

    result.duration = round(time.monotonic() - start, 2)
    return result


async def scan_user(
    username: str,
    token:    Optional[str] = None,
) -> ScanResult:
    """Scan all public repositories of a GitHub user."""
    start  = time.monotonic()
    client = GitHubClient(token)
    result = ScanResult(target=f"github.com/{username}", scan_type="user")

    async with aiohttp.ClientSession() as session:
        repos = await client.get_user_repos(session, username)

    if not repos:
        result.errors.append(f"No public repositories found for '{username}'")
        result.duration = round(time.monotonic() - start, 2)
        return result

    for repo_info in repos:
        owner    = repo_info["owner"]["login"]
        repo     = repo_info["name"]
        try:
            findings, files = await _scan_single_repo(client, owner, repo)
            result.findings.extend(findings)
            result.total_files += files
        except PermissionError as e:
            result.errors.append(str(e))
            break
        except Exception as e:
            logger.warning("Error scanning %s/%s: %s", owner, repo, e)
            result.errors.append(f"Skipped {repo}: {e}")

    result.duration = round(time.monotonic() - start, 2)
    return result


async def verify_github_token(token: str) -> bool:
    """Public helper — verify a user-submitted GitHub token."""
    client = GitHubClient()
    return await client.verify_token(token)
