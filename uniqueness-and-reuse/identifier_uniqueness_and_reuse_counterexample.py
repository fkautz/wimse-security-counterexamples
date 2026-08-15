#!/usr/bin/env python3
"""Reproduce origin-wide allocation and identifier reuse failures."""

from dataclasses import dataclass, replace
from typing import Iterable


IDENTIFIER = "wimse://example.org/service/payments"
OTHER_IDENTIFIER = "wimse://example.org/service/reporting"


@dataclass(frozen=True)
class Allocation:
    issuer: str
    principal: str
    identifier: str


@dataclass(frozen=True)
class ReuseAttempt:
    identifier: str
    previous_principal: str
    next_principal: str
    intentional: bool
    previous_credential_valid: bool
    previous_proof_valid: bool
    authorization_cache_active: bool
    external_mapping_active: bool
    updates_propagated: bool
    audit_attribution_preserved: bool


COLLIDING_ALLOCATIONS = (
    Allocation("issuer-a", "P0", IDENTIFIER),
    Allocation("issuer-b", "P1", IDENTIFIER),
)
SHARED_PRINCIPAL_ALLOCATIONS = (
    Allocation("issuer-a", "P0", IDENTIFIER),
    Allocation("issuer-b", "P0", IDENTIFIER),
)

UNSAFE_REUSE = ReuseAttempt(
    identifier=OTHER_IDENTIFIER,
    previous_principal="P0",
    next_principal="P1",
    intentional=True,
    previous_credential_valid=True,
    previous_proof_valid=True,
    authorization_cache_active=True,
    external_mapping_active=True,
    updates_propagated=False,
    audit_attribution_preserved=False,
)
SAFE_REUSE = replace(
    UNSAFE_REUSE,
    previous_credential_valid=False,
    previous_proof_valid=False,
    authorization_cache_active=False,
    external_mapping_active=False,
    updates_propagated=True,
    audit_attribution_preserved=True,
)
SAME_PRINCIPAL_ROTATION = replace(
    UNSAFE_REUSE,
    next_principal="P0",
)


def issuer_local_unique(allocations: Iterable[Allocation], issuer: str) -> bool:
    """Each identifier maps to at most one principal in one issuer's records."""
    issuer_allocations = [item for item in allocations if item.issuer == issuer]
    identifiers = {item.identifier for item in issuer_allocations}
    return all(
        len(
            {
                item.principal
                for item in issuer_allocations
                if item.identifier == identifier
            }
        )
        <= 1
        for identifier in identifiers
    )


def origin_wide_unique(allocations: Iterable[Allocation]) -> bool:
    """Each complete identifier maps to at most one logical principal."""
    allocation_list = list(allocations)
    identifiers = {item.identifier for item in allocation_list}
    return all(
        len(
            {
                item.principal
                for item in allocation_list
                if item.identifier == identifier
            }
        )
        <= 1
        for identifier in identifiers
    )


def weak_allocation_accepts(allocations: Iterable[Allocation]) -> bool:
    """Accept when every issuer independently preserves local uniqueness."""
    allocation_list = list(allocations)
    issuers = {item.issuer for item in allocation_list}
    return all(
        issuer_local_unique(allocation_list, issuer) for issuer in issuers
    )


def strict_allocation_accepts(allocations: Iterable[Allocation]) -> bool:
    allocation_list = list(allocations)
    return weak_allocation_accepts(allocation_list) and origin_wide_unique(
        allocation_list
    )


def weak_reassignment_accepts(attempt: ReuseAttempt) -> bool:
    """Treat operator intent as sufficient authorization to reuse an identity."""
    return attempt.intentional


def strict_reassignment_accepts(attempt: ReuseAttempt) -> bool:
    """Require all prior-principal state to be retired before reassignment."""
    if attempt.previous_principal == attempt.next_principal:
        return True
    return (
        attempt.intentional
        and not attempt.previous_credential_valid
        and not attempt.previous_proof_valid
        and not attempt.authorization_cache_active
        and not attempt.external_mapping_active
        and attempt.updates_propagated
        and attempt.audit_attribution_preserved
    )


def weak_policy_allows_old_principal(attempt: ReuseAttempt) -> bool:
    """Use a valid old credential with privileges assigned after reuse."""
    return (
        attempt.previous_credential_valid
        and weak_reassignment_accepts(attempt)
        and attempt.previous_principal != attempt.next_principal
    )


def strict_policy_allows_old_principal(attempt: ReuseAttempt) -> bool:
    return (
        attempt.previous_credential_valid
        and strict_reassignment_accepts(attempt)
        and attempt.previous_principal != attempt.next_principal
    )


def main() -> None:
    issuer_a_unique = issuer_local_unique(COLLIDING_ALLOCATIONS, "issuer-a")
    issuer_b_unique = issuer_local_unique(COLLIDING_ALLOCATIONS, "issuer-b")
    global_unique = origin_wide_unique(COLLIDING_ALLOCATIONS)
    weak_allocation = weak_allocation_accepts(COLLIDING_ALLOCATIONS)
    strict_allocation = strict_allocation_accepts(COLLIDING_ALLOCATIONS)

    print(f"multi_issuer.issuer_a_local_unique: {str(issuer_a_unique).lower()}")
    print(f"multi_issuer.issuer_b_local_unique: {str(issuer_b_unique).lower()}")
    print(f"multi_issuer.origin_wide_unique: {str(global_unique).lower()}")
    print(
        f"multi_issuer.weak_allocation: "
        f"{'ACCEPT' if weak_allocation else 'REJECT'}"
    )
    print(
        f"multi_issuer.strict_allocation: "
        f"{'ACCEPT' if strict_allocation else 'REJECT'}"
    )

    print(f"reuse.intentional: {str(UNSAFE_REUSE.intentional).lower()}")
    print(
        "reuse.old_credential_valid: "
        f"{str(UNSAFE_REUSE.previous_credential_valid).lower()}"
    )
    print(
        "reuse.safe_to_reassign: "
        f"{str(strict_reassignment_accepts(UNSAFE_REUSE)).lower()}"
    )
    print(
        "reuse.weak_reassignment: "
        f"{'ACCEPT' if weak_reassignment_accepts(UNSAFE_REUSE) else 'REJECT'}"
    )
    print(
        "reuse.strict_reassignment: "
        f"{'ACCEPT' if strict_reassignment_accepts(UNSAFE_REUSE) else 'REJECT'}"
    )
    print(
        "reuse.weak_policy: "
        f"{'ALLOW' if weak_policy_allows_old_principal(UNSAFE_REUSE) else 'DENY'}"
    )
    print(
        "reuse.strict_policy: "
        f"{'ALLOW' if strict_policy_allows_old_principal(UNSAFE_REUSE) else 'DENY'}"
    )

    shared_accepted = strict_allocation_accepts(SHARED_PRINCIPAL_ALLOCATIONS)
    safe_reuse_accepted = strict_reassignment_accepts(SAFE_REUSE)
    rotation_accepted = strict_reassignment_accepts(SAME_PRINCIPAL_ROTATION)
    print(
        "shared_principal.strict_allocation: "
        f"{'ACCEPT' if shared_accepted else 'REJECT'}"
    )
    print(
        "safe_reassignment.strict_reassignment: "
        f"{'ACCEPT' if safe_reuse_accepted else 'REJECT'}"
    )
    print(
        "same_principal_rotation.strict_reassignment: "
        f"{'ACCEPT' if rotation_accepted else 'REJECT'}"
    )
    print(
        "security_result: unrelated principals received one identifier or "
        "inherited its privileges"
    )

    allocation_reproduced = (
        issuer_a_unique
        and issuer_b_unique
        and not global_unique
        and weak_allocation
        and not strict_allocation
    )
    reuse_reproduced = (
        weak_reassignment_accepts(UNSAFE_REUSE)
        and not strict_reassignment_accepts(UNSAFE_REUSE)
        and weak_policy_allows_old_principal(UNSAFE_REUSE)
        and not strict_policy_allows_old_principal(UNSAFE_REUSE)
    )
    controls_pass = shared_accepted and safe_reuse_accepted and rotation_accepted
    if not allocation_reproduced or not reuse_reproduced or not controls_pass:
        raise SystemExit("counterexamples did not reproduce")


if __name__ == "__main__":
    main()
