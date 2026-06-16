"""
core/validator.py
Post-match false-positive filtering and safe value masking.

After regex/entropy matches, this module:
  1. Filters obvious false positives (placeholder values, example strings)
  2. Masks the raw matched value for safe storage and display
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# FALSE POSITIVE FILTERS
# ─────────────────────────────────────────────────────────────────────────────

# Exact strings that are placeholder / documentation examples
_PLACEHOLDER_EXACT: frozenset[str] = frozenset({
    "your_api_key_here",
    "your-api-key",
    "insert_key_here",
    "replace_with_your_key",
    "enter_your_key",
    "xxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "000000000000000000000000",
    "11111111111111111111111",
    "aaaaaaaaaaaaaaaaaaaaaaaa",
    "changeme",
    "change_me",
    "todo",
    "fixme",
    "placeholder",
    "example",
    "test",
    "demo",
    "sample",
    "dummy",
    "fake",
    "mock",
    "n/a",
    "na",
    "none",
    "null",
    "undefined",
    "secret",           # bare word "secret" as a value
    "password",         # bare word
    "apikey",           # bare word
    "token",            # bare word
    "<your_token>",
    "<api_key>",
    "<secret>",
    "${api_key}",
    "${secret}",
    "${token}",
    "$(api_key)",
    "env.api_key",
    "process.env.api_key",
    "os.environ['api_key']",
})

# Regex patterns that indicate placeholder / template values
_PLACEHOLDER_RE: list[re.Pattern] = [
    re.compile(r"^\$\{[a-zA-Z_][a-zA-Z0-9_]*\}$"),           # ${VAR_NAME}
    re.compile(r"^\$[A-Z_][A-Z0-9_]*$"),                      # $ENV_VAR
    re.compile(r"^<[a-zA-Z_][a-zA-Z0-9_\- ]*>$"),            # <placeholder>
    re.compile(r"^%[a-zA-Z_][a-zA-Z0-9_]*%$"),               # %WINDOWS_VAR%
    re.compile(r"^#{[a-zA-Z_][a-zA-Z0-9_]*}$"),              # #{ruby_template}
    re.compile(r"^{{[a-zA-Z_][a-zA-Z0-9_. ]*}}$"),           # {{jinja_var}}
    re.compile(r"^[xX]{8,}$"),                                 # XXXXXXXX
    re.compile(r"^[0]{8,}$"),                                  # 00000000
    re.compile(r"^[1]{8,}$"),                                  # 11111111
    re.compile(r"^\*{6,}$"),                                   # ******
    re.compile(r"^\.{6,}$"),                                   # ......
    re.compile(r"^(?:your|my|the|an?)[_\- ][a-z_\- ]+$", re.I),  # your_key_here
    re.compile(r"^\[?[a-zA-Z_][a-zA-Z0-9_\- ]*\]?$"),        # [placeholder]
    re.compile(r"^[a-zA-Z]+_(?:here|key|secret|token|value)$", re.I),  # insert_here
]

# Values found in test/example files that are known safe
_KNOWN_TEST_VALUES: frozenset[str] = frozenset({
    # Stripe test keys
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    # Common example AWS key
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # GitHub docs example
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
})

# File paths that are unlikely to contain real secrets
_SAFE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:test|spec|mock|fixture|example|sample|doc|readme|changelog)", re.I),
    re.compile(r"__tests__"),
    re.compile(r"\.test\.[a-z]+$", re.I),
    re.compile(r"\.spec\.[a-z]+$", re.I),
]


def is_false_positive(value: str, file_path: str = "") -> bool:
    """
    Return True if the matched value is almost certainly NOT a real secret.

    Args:
        value:      The raw matched string extracted by regex/entropy.
        file_path:  The file path where the match was found (optional).
    """
    stripped = value.strip().strip("'\"` ")

    # 1. Too short or too long to be a real secret
    if len(stripped) < 8 or len(stripped) > 500:
        return True

    # 2. Exact placeholder match (case-insensitive)
    if stripped.lower() in _PLACEHOLDER_EXACT:
        return True

    # 3. Known safe test values
    if stripped in _KNOWN_TEST_VALUES:
        return True

    # 4. Placeholder pattern match
    for pat in _PLACEHOLDER_RE:
        if pat.match(stripped):
            return True

    # 5. Found in a test/example file path
    if file_path:
        for path_pat in _SAFE_PATH_PATTERNS:
            if path_pat.search(file_path):
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# VALUE MASKING (safe for storage and display)
# ─────────────────────────────────────────────────────────────────────────────

def mask_secret(value: str) -> str:
    """
    Return a masked version of a secret suitable for display and storage.

    Rules:
      - Short (< 12 chars): show first 2 + ***
      - Medium (12–40 chars): show first 4 + *** + last 2
      - Long (> 40 chars): show first 6 + *** + last 4
    """
    v = value.strip()
    length = len(v)

    if length < 12:
        return v[:2] + "***"
    elif length <= 40:
        return v[:4] + "***" + v[-2:]
    else:
        return v[:6] + "***" + v[-4:]


def extract_match_value(match: re.Match) -> str:
    """
    Extract the most relevant capture group from a regex match.
    Falls back to the full match if no groups are captured.
    """
    groups = [g for g in match.groups() if g is not None]
    if groups:
        # Return the longest non-None group (most specific capture)
        return max(groups, key=len)
    return match.group(0)
