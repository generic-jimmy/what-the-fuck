"""
core/entropy.py
Shannon entropy analysis — catches high-randomness strings
that don't match any known regex pattern but look like secrets.
"""

import math
import re
from dataclasses import dataclass

# Minimum length for a string to be considered for entropy analysis
MIN_SECRET_LENGTH = 20
MAX_SECRET_LENGTH = 200

# Entropy threshold — strings with entropy above this value are flagged
# (true random base64/hex strings typically score 4.5–6.0)
ENTROPY_THRESHOLD = 4.5

# Character sets for categorised entropy scoring
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS    = set("0123456789abcdefABCDEF")
ALPHANUM     = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

# Patterns that isolate candidate secret tokens from surrounding code
_TOKEN_RE = re.compile(
    r"""(?:['"`]|:=|=\s*['"`]?)([a-zA-Z0-9+/=_\-]{20,200})(?:['"`]|$)""",
    re.MULTILINE,
)

# Context keywords that strongly suggest the adjacent string is a secret
CONTEXT_KEYWORDS = frozenset({
    "key", "secret", "token", "password", "passwd", "pwd", "api",
    "auth", "credential", "cred", "access", "private", "sign",
    "bearer", "jwt", "hmac", "salt", "seed", "pass",
})


@dataclass
class EntropyFinding:
    value: str
    entropy: float
    line_number: int
    context: str        # surrounding line for display


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    counter: dict[str, int] = {}
    for ch in data:
        counter[ch] = counter.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def _has_secret_context(line: str, token: str) -> bool:
    """
    Return True if the line contains a context keyword near the token,
    suggesting the string is intentionally a secret value.
    """
    # Look at the 60 chars before the token
    idx = line.find(token)
    prefix = line[max(0, idx - 60): idx].lower()
    return any(kw in prefix for kw in CONTEXT_KEYWORDS)


def _is_likely_false_positive(token: str) -> bool:
    """Filter out common high-entropy strings that are NOT secrets."""
    # Skip short tokens (already handled by MIN_SECRET_LENGTH)
    if len(token) < MIN_SECRET_LENGTH:
        return True

    # Skip very long tokens (likely binary blobs / base64 images)
    if len(token) > MAX_SECRET_LENGTH:
        return True

    # Skip strings that look like hashes in comments/logs (only hex)
    if all(c in HEX_CHARS for c in token) and len(token) in {32, 40, 56, 64, 128}:
        # Could be an MD5/SHA hash — still flag but lower confidence
        return False

    # Skip obvious file paths
    if "/" in token or "\\" in token:
        return True

    # Skip URL-like strings
    if token.startswith(("http", "ftp", "www")):
        return True

    # Skip repetitive patterns (e.g. "AAAA..." or "0000...")
    unique_ratio = len(set(token)) / len(token)
    if unique_ratio < 0.3:
        return True

    return False


def analyse_line(line: str, line_number: int) -> list[EntropyFinding]:
    """
    Scan a single line for high-entropy tokens.
    Returns a list of EntropyFinding objects.
    """
    findings: list[EntropyFinding] = []

    for match in _TOKEN_RE.finditer(line):
        token = match.group(1)

        if _is_likely_false_positive(token):
            continue

        # Only score tokens using known secret character sets
        char_set = set(token)
        if not (char_set <= BASE64_CHARS or char_set <= ALPHANUM):
            continue

        score = shannon_entropy(token)
        if score >= ENTROPY_THRESHOLD:
            # Require context keyword to reduce noise
            if _has_secret_context(line, token):
                findings.append(
                    EntropyFinding(
                        value=token,
                        entropy=round(score, 3),
                        line_number=line_number,
                        context=line.strip()[:120],
                    )
                )

    return findings


def analyse_file_content(content: str) -> list[EntropyFinding]:
    """
    Run entropy analysis across all lines of a file.
    Returns a deduplicated list of EntropyFindings.
    """
    all_findings: list[EntropyFinding] = []
    seen: set[str] = set()

    for line_num, line in enumerate(content.splitlines(), start=1):
        for finding in analyse_line(line, line_num):
            if finding.value not in seen:
                seen.add(finding.value)
                all_findings.append(finding)

    return all_findings
