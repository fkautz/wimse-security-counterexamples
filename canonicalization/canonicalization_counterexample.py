#!/usr/bin/env python3
"""Reproduce an authorization collision caused by inconsistent URI equality.

The example starts after credential signature validation. It demonstrates that
successful cryptographic validation does not prevent a later identifier
comparison from merging two issuer-distinct subjects.
"""

from dataclasses import dataclass
import re
from urllib.parse import unquote, urlsplit


CANONICAL_SUBJECT = "wimse://trust.example/service/payment"
NON_CANONICAL_SUBJECT = "wimse://trust.example/service/%70ayment"

_AUTHORITY = re.compile(r"[a-z0-9._-]+")
_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")


@dataclass(frozen=True)
class ValidatedCredential:
    principal: str
    subject: str
    signature_valid: bool = True


def weak_identity_key(subject: str) -> str:
    """Approximate a consumer that decodes a URI before authorization."""
    parsed = urlsplit(subject)
    return f"{parsed.scheme}://{parsed.netloc}{unquote(parsed.path)}"


def is_canonical_wimse_identifier(subject: str) -> bool:
    """Apply the canonical profile proposed by the specification change."""
    try:
        subject.encode("ascii")
    except UnicodeEncodeError:
        return False

    prefix = "wimse://"
    if not subject.startswith(prefix):
        return False

    authority, separator, path = subject[len(prefix) :].partition("/")
    if not separator or not path:
        return False
    if not _AUTHORITY.fullmatch(authority) or authority.endswith("."):
        return False

    segments = path.split("/")
    return all(
        segment not in {"", ".", ".."} and _SEGMENT.fullmatch(segment)
        for segment in segments
    )


def weak_policy_allows(credential: ValidatedCredential) -> bool:
    """Authorize by a normalized key after signature validation."""
    privileged = {CANONICAL_SUBJECT}
    return (
        credential.signature_valid
        and weak_identity_key(credential.subject) in privileged
    )


def strict_policy_allows(credential: ValidatedCredential) -> bool:
    """Reject non-canonical subjects, then compare the complete value."""
    privileged = {CANONICAL_SUBJECT}
    return (
        credential.signature_valid
        and is_canonical_wimse_identifier(credential.subject)
        and credential.subject in privileged
    )


def main() -> None:
    credential = ValidatedCredential(
        principal="reporting",
        subject=NON_CANONICAL_SUBJECT,
    )
    issuer_distinct = CANONICAL_SUBJECT != NON_CANONICAL_SUBJECT
    normalized_equal = weak_identity_key(CANONICAL_SUBJECT) == weak_identity_key(
        NON_CANONICAL_SUBJECT
    )
    weak_allowed = weak_policy_allows(credential)
    strict_allowed = strict_policy_allows(credential)

    print(f"issuer_distinct: {str(issuer_distinct).lower()}")
    print(f"weak_normalized_equal: {str(normalized_equal).lower()}")
    print(f"weak_policy: {'ALLOW' if weak_allowed else 'DENY'}")
    print(f"strict_policy: {'ALLOW' if strict_allowed else 'DENY'}")
    print(
        "security_result: non-canonical identity received canonical identity privileges"
    )

    if not (issuer_distinct and normalized_equal and weak_allowed and not strict_allowed):
        raise SystemExit("counterexample did not reproduce")


if __name__ == "__main__":
    main()
