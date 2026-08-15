#!/usr/bin/env python3
"""Reproduce authorization expansion caused by unsafe prefix matching."""

from dataclasses import dataclass
from typing import Callable, Optional, Tuple
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HierarchicalPolicy:
    root_identifier: str
    enabled: bool = True
    allow_entire_origin: bool = False


@dataclass(frozen=True)
class AttackCase:
    name: str
    policy: HierarchicalPolicy
    subject: str
    weak_matcher: Callable[[HierarchicalPolicy, str], bool]
    credential_valid: bool = True


POLICY_ROOT = "wimse://trust.example/service/pay"
POLICY = HierarchicalPolicy(POLICY_ROOT)

SIBLING_SUFFIX = "wimse://trust.example/service/payroll-attacker"
DOT_SEGMENT_ESCAPE = "wimse://trust.example/service/pay/../admin"
ENCODED_DOT_SEGMENT_ESCAPE = (
    "wimse://trust.example/service/pay/%2e%2e/admin"
)
ORIGIN_SUBSTITUTION = "wimse://attacker.example/service/pay/worker"
AUTHORIZED_DESCENDANT = "wimse://trust.example/service/pay/worker"
EMPTY_PATH_POLICY = HierarchicalPolicy("wimse://trust.example")
ROOT_PATH_POLICY = HierarchicalPolicy("wimse://trust.example/")


def same_origin(left: str, right: str) -> bool:
    left_uri = urlsplit(left)
    right_uri = urlsplit(right)
    return (left_uri.scheme, left_uri.netloc) == (
        right_uri.scheme,
        right_uri.netloc,
    )


def weak_raw_prefix_allows(policy: HierarchicalPolicy, subject: str) -> bool:
    """Treat a character prefix as a hierarchy."""
    return policy.enabled and subject.startswith(policy.root_identifier)


def weak_path_only_prefix_allows(
    policy: HierarchicalPolicy, subject: str
) -> bool:
    """Ignore the origin and compare only raw path text."""
    policy_path = urlsplit(policy.root_identifier).path
    subject_path = urlsplit(subject).path
    return policy.enabled and subject_path.startswith(policy_path)


def validated_path_segments(identifier: str) -> Optional[Tuple[str, ...]]:
    """Reject path forms that can change segment boundaries after matching."""
    parsed = urlsplit(identifier)
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.query or parsed.fragment or "%" in parsed.path:
        return None
    if parsed.path in {"", "/"}:
        return ()
    if not parsed.path.startswith("/"):
        return None

    segments = tuple(parsed.path[1:].split("/"))
    if any(segment in {"", ".", ".."} for segment in segments):
        return None
    return segments


def strict_segment_policy_allows(
    policy: HierarchicalPolicy, subject: str
) -> bool:
    """Match one exact origin using complete validated path segments."""
    if not policy.enabled or not same_origin(policy.root_identifier, subject):
        return False

    root_segments = validated_path_segments(policy.root_identifier)
    subject_segments = validated_path_segments(subject)
    if root_segments is None or subject_segments is None:
        return False
    if not root_segments and not policy.allow_entire_origin:
        return False

    return (
        len(subject_segments) >= len(root_segments)
        and subject_segments[: len(root_segments)] == root_segments
    )


def weak_policy_allows(case: AttackCase) -> bool:
    return case.credential_valid and case.weak_matcher(case.policy, case.subject)


def strict_policy_allows(case: AttackCase) -> bool:
    return case.credential_valid and strict_segment_policy_allows(
        case.policy, case.subject
    )


ATTACK_CASES = (
    AttackCase("sibling_suffix", POLICY, SIBLING_SUFFIX, weak_raw_prefix_allows),
    AttackCase(
        "dot_segment_escape", POLICY, DOT_SEGMENT_ESCAPE, weak_raw_prefix_allows
    ),
    AttackCase(
        "encoded_dot_segment_escape",
        POLICY,
        ENCODED_DOT_SEGMENT_ESCAPE,
        weak_raw_prefix_allows,
    ),
    AttackCase(
        "origin_substitution",
        POLICY,
        ORIGIN_SUBSTITUTION,
        weak_path_only_prefix_allows,
    ),
)


def print_result(case: AttackCase) -> None:
    print(f"{case.name}.credential_valid: {str(case.credential_valid).lower()}")
    print(f"{case.name}.policy_enabled: {str(case.policy.enabled).lower()}")
    print(
        f"{case.name}.same_origin: "
        f"{str(same_origin(case.policy.root_identifier, case.subject)).lower()}"
    )
    print(
        f"{case.name}.weak_policy: "
        f"{'ALLOW' if weak_policy_allows(case) else 'DENY'}"
    )
    print(
        f"{case.name}.strict_policy: "
        f"{'ALLOW' if strict_policy_allows(case) else 'DENY'}"
    )


def main() -> None:
    for case in ATTACK_CASES:
        print_result(case)

    for name, policy in (
        ("empty_path", EMPTY_PATH_POLICY),
        ("root_path", ROOT_PATH_POLICY),
    ):
        fail_open = weak_raw_prefix_allows(policy, AUTHORIZED_DESCENDANT)
        fail_closed = strict_segment_policy_allows(
            policy,
            AUTHORIZED_DESCENDANT,
        )
        explicit_originwide = strict_segment_policy_allows(
            HierarchicalPolicy(
                policy.root_identifier,
                allow_entire_origin=True,
            ),
            AUTHORIZED_DESCENDANT,
        )
        print(f"{name}.fail_open_policy: {'ALLOW' if fail_open else 'DENY'}")
        print(
            f"{name}.fail_closed_default: "
            f"{'ALLOW' if fail_closed else 'DENY'}"
        )
        print(
            f"{name}.explicit_originwide: "
            f"{'ALLOW' if explicit_originwide else 'DENY'}"
        )

    authorized = strict_segment_policy_allows(POLICY, AUTHORIZED_DESCENDANT)
    disabled = strict_segment_policy_allows(
        HierarchicalPolicy(POLICY_ROOT, enabled=False),
        AUTHORIZED_DESCENDANT,
    )
    print(f"authorized_descendant.strict_policy: {'ALLOW' if authorized else 'DENY'}")
    print(f"disabled_policy.strict_policy: {'ALLOW' if disabled else 'DENY'}")
    print(
        "security_result: raw prefix policies granted privileges outside "
        "the configured hierarchy"
    )

    reproduced = all(
        weak_policy_allows(case) and not strict_policy_allows(case)
        for case in ATTACK_CASES
    )
    originwide_controls = all(
        weak_raw_prefix_allows(policy, AUTHORIZED_DESCENDANT)
        and not strict_segment_policy_allows(policy, AUTHORIZED_DESCENDANT)
        and strict_segment_policy_allows(
            HierarchicalPolicy(
                policy.root_identifier,
                allow_entire_origin=True,
            ),
            AUTHORIZED_DESCENDANT,
        )
        for policy in (EMPTY_PATH_POLICY, ROOT_PATH_POLICY)
    )
    if not reproduced or not originwide_controls or not authorized or disabled:
        raise SystemExit("counterexamples did not reproduce")


if __name__ == "__main__":
    main()
