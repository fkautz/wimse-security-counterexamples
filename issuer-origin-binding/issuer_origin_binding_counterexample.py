#!/usr/bin/env python3
"""Reproduce authorization failures caused by missing issuer-origin binding."""

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Origin:
    scheme: str
    authority: str


@dataclass(frozen=True)
class ValidatedCredential:
    issuer: str
    subject: str
    signature_valid: bool = True


SPIFFE_ISSUER = "issuer-for-spiffe-trust"
DEV_WIMSE_ISSUER = "issuer-for-wimse-dev"
PROD_WIMSE_ISSUER = "issuer-for-wimse-prod"

PAYMENT_SUBJECT = "wimse://trust.example/service/payment"
ADMIN_SUBJECT = "wimse://prod.example/service/admin"

ACCEPTED_ISSUERS = {
    SPIFFE_ISSUER,
    DEV_WIMSE_ISSUER,
    PROD_WIMSE_ISSUER,
}
TRUSTED_AUTHORITIES = {"trust.example", "prod.example"}
TRUSTED_ORIGINS = {
    Origin("wimse", "trust.example"),
    Origin("wimse", "prod.example"),
}
AUTHORIZED_ORIGINS_BY_ISSUER = {
    SPIFFE_ISSUER: {Origin("spiffe", "trust.example")},
    DEV_WIMSE_ISSUER: {Origin("wimse", "dev.example")},
    PROD_WIMSE_ISSUER: {Origin("wimse", "prod.example")},
}
PRIVILEGED_IDENTIFIERS = {PAYMENT_SUBJECT, ADMIN_SUBJECT}

CROSS_SCHEME_CREDENTIAL = ValidatedCredential(
    issuer=SPIFFE_ISSUER,
    subject=PAYMENT_SUBJECT,
)
CROSS_AUTHORITY_CREDENTIAL = ValidatedCredential(
    issuer=DEV_WIMSE_ISSUER,
    subject=ADMIN_SUBJECT,
)
AUTHORIZED_CONTROL_CREDENTIAL = ValidatedCredential(
    issuer=PROD_WIMSE_ISSUER,
    subject=ADMIN_SUBJECT,
)


def origin_of(subject: str) -> Origin:
    """Extract the scheme and authority that define the identifier origin."""
    parsed = urlsplit(subject)
    return Origin(parsed.scheme, parsed.netloc)


def issuer_accepted(credential: ValidatedCredential) -> bool:
    return credential.issuer in ACCEPTED_ISSUERS


def authority_trusted(credential: ValidatedCredential) -> bool:
    return origin_of(credential.subject).authority in TRUSTED_AUTHORITIES


def issuer_authorized_for_subject_origin(credential: ValidatedCredential) -> bool:
    return origin_of(credential.subject) in AUTHORIZED_ORIGINS_BY_ISSUER.get(
        credential.issuer, set()
    )


def weak_policy_allows(credential: ValidatedCredential) -> bool:
    """Authorize after independent signature, issuer, and authority checks."""
    return (
        credential.signature_valid
        and issuer_accepted(credential)
        and authority_trusted(credential)
        and credential.subject in PRIVILEGED_IDENTIFIERS
    )


def strict_policy_allows(credential: ValidatedCredential) -> bool:
    """Require the issuer to be authorized for the exact subject origin."""
    subject_origin = origin_of(credential.subject)
    return (
        credential.signature_valid
        and issuer_accepted(credential)
        and subject_origin in TRUSTED_ORIGINS
        and issuer_authorized_for_subject_origin(credential)
        and credential.subject in PRIVILEGED_IDENTIFIERS
    )


def print_result(name: str, credential: ValidatedCredential) -> None:
    print(f"{name}.signature_valid: {str(credential.signature_valid).lower()}")
    print(f"{name}.issuer_accepted: {str(issuer_accepted(credential)).lower()}")
    print(f"{name}.authority_trusted: {str(authority_trusted(credential)).lower()}")
    print(
        f"{name}.issuer_origin_authorized: "
        f"{str(issuer_authorized_for_subject_origin(credential)).lower()}"
    )
    print(
        f"{name}.weak_policy: "
        f"{'ALLOW' if weak_policy_allows(credential) else 'DENY'}"
    )
    print(
        f"{name}.strict_policy: "
        f"{'ALLOW' if strict_policy_allows(credential) else 'DENY'}"
    )


def main() -> None:
    attacks = {
        "cross_scheme": CROSS_SCHEME_CREDENTIAL,
        "cross_authority": CROSS_AUTHORITY_CREDENTIAL,
    }

    for name, credential in attacks.items():
        print_result(name, credential)

    control_allowed = strict_policy_allows(AUTHORIZED_CONTROL_CREDENTIAL)
    print(f"authorized_control.strict_policy: {'ALLOW' if control_allowed else 'DENY'}")
    print(
        "security_result: accepted issuers asserted privileged identities "
        "outside their authorized origins"
    )

    reproduced = all(
        weak_policy_allows(credential)
        and not strict_policy_allows(credential)
        and not issuer_authorized_for_subject_origin(credential)
        for credential in attacks.values()
    )
    if not reproduced or not control_allowed:
        raise SystemExit("counterexamples did not reproduce")


if __name__ == "__main__":
    main()
