"""Filter failure evidence before logs reach stdout or a persisted artifact."""

import os
import re
import sys
from collections.abc import Mapping

MAX_INPUT_CHARS = 2_000_000


def sanitize_text(text: str, environment: Mapping[str, str] | None = None) -> str:
    """Remove credentials, keys, addresses and absolute paths from diagnostic text."""
    environment = os.environ if environment is None else environment
    for name, value in environment.items():
        if value and re.search(
            r"PASS(?:WORD)?|TOKEN|SECRET|PRIVATE|PSK|CREDENTIAL|SSH_KEY|SSH_USER|ADMIN_USER|BASE_URL|SERVER_HOST",
            name,
            re.IGNORECASE,
        ):
            text = text.replace(value, "<redacted-secret>")
    text = re.sub(
        r"-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH)[^-]*-----.*?(?:-----END [^-]+-----|\Z)",
        "<redacted-key>",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(r"\b[a-z][a-z0-9+.-]*://[^\s<>]+", "<redacted-url>", text, flags=re.I)
    text = re.sub(r"\b(?:Bearer|Basic)\s+[^\s,;]+", "<redacted-auth>", text, flags=re.I)
    secret_name = (
        r"password|passwd|passphrase|token|secret|authorization|cookie|credential|"
        r"private[_ -]?key|public[_ -]?key|peer[_ -]?key|preshared[_ -]?key|psk|username|"
        r"endpoint|ssh[_ -]?host|server[_ -]?host"
    )
    text = re.sub(
        rf"([\"']?(?:{secret_name})[\"']?\s*[:=]\s*)"
        r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}]+)",
        r"\1<redacted-value>",
        text,
        flags=re.I,
    )
    # AWG keys can occur without a field name in wrapped protocol errors.
    text = re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])", "<redacted-key>", text)
    text = re.sub(r"\b[0-9a-f]{64}\b", "<redacted-key>", text, flags=re.I)
    text = re.sub(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", "<redacted-address>", text)
    text = re.sub(
        r"(?<![\w])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.%]*(?![\w])",
        "<redacted-address>",
        text,
        flags=re.I,
    )
    # Include DNS endpoints and email addresses; plain error types remain readable.
    text = re.sub(
        r"\b(?:[a-z0-9._+-]+@)?(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*\b",
        "<redacted-address>",
        text,
        flags=re.I,
    )
    text = re.sub(r"""["'](?:[A-Za-z]:[\\/]|/)[^"'\r\n]*["']""", "<redacted-path>", text)
    text = re.sub(r"(?<![\w])(?:[A-Za-z]:[\\/]|/)[^\s\"'<>]*", "<redacted-path>", text)
    # Prevent terminal escapes and forged workflow annotations from raw service text.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"[^\S\n\t ]|[\x00-\x08\x0b-\x1f\x7f]", "", text)
    return text.replace("::", ": :")


def main() -> int:
    """Read a bounded stdin stream and emit only sanitized diagnostic evidence."""
    text = sys.stdin.read(MAX_INPUT_CHARS + 1)
    truncated = len(text) > MAX_INPUT_CHARS
    if truncated:
        # A split key or environment secret might evade whole-value matching.
        # Keep only complete lines, then sanitize the retained evidence.
        text = text[:MAX_INPUT_CHARS]
        last_newline = text.rfind("\n")
        text = text[: last_newline + 1] if last_newline >= 0 else ""
    sys.stdout.write(sanitize_text(text))
    if truncated:
        sys.stdout.write("\n[service evidence truncated]\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError):
        sys.stderr.write("Service evidence sanitization failed; raw evidence suppressed.\n")
        raise SystemExit(1) from None
