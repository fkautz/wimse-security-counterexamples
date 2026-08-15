# Identifier uniqueness and reuse

These counterexamples demonstrate two failures that merge unrelated workload
security principals under one Workload Identifier.

## Multi-issuer allocation collision

Two issuers consult independent allocation records:

| Issuer | Local result | Assignment |
| --- | --- | --- |
| Issuer A | Unused | Principal P0 |
| Issuer B | Unused | Principal P1 |

Both assign:

```text
wimse://example.org/service/payments
```

Each issuer preserves local uniqueness. Origin-wide uniqueness fails because
the complete identifier represents two different principals.

## Unsafe identifier reassignment

| Step | State |
| --- | --- |
| 1 | The identifier represents P0, which holds a valid credential. |
| 2 | The identifier is intentionally reassigned to P1. |
| 3 | Authorization policy grants the identifier P1's privileges. |
| 4 | P0 presents its unexpired credential and receives P1's privileges. |

The credential is valid and has not been forged. Intentional reassignment does
not retire credentials, proofs, caches, mappings, or audit state belonging to
the previous principal.

## Run

```sh
python3 identifier_uniqueness_and_reuse_counterexample.py
```

Expected output:

```text
multi_issuer.issuer_a_local_unique: true
multi_issuer.issuer_b_local_unique: true
multi_issuer.origin_wide_unique: false
multi_issuer.weak_allocation: ACCEPT
multi_issuer.strict_allocation: REJECT
reuse.intentional: true
reuse.old_credential_valid: true
reuse.safe_to_reassign: false
reuse.weak_reassignment: ACCEPT
reuse.strict_reassignment: REJECT
reuse.weak_policy: ALLOW
reuse.strict_policy: DENY
shared_principal.strict_allocation: ACCEPT
safe_reassignment.strict_reassignment: ACCEPT
same_principal_rotation.strict_reassignment: ACCEPT
security_result: unrelated principals received one identifier or inherited its privileges
```

Run the regression tests:

```sh
python3 -m unittest -v test_identifier_uniqueness_and_reuse_counterexample.py
```

## Risk

Authorization, revocation, mapping, caching, and auditing commonly use the
complete Workload Identifier as the principal key. An allocation collision or
premature reassignment causes those systems to merge unrelated principals.
Neither attack requires credential forgery or signing-key compromise.

Local uniqueness is like two vehicle-registration offices assigning plates
from separate spreadsheets. Each office can avoid duplicates locally while
the shared namespace still contains a collision.

Unsafe reuse is like reassigning an employee number while the former
employee's badge still opens doors.

## Required rules

All issuers for an origin coordinate allocations or use provably disjoint
namespaces. One complete identifier represents at most one logical security
principal at a time.

An identifier is not reassigned to a different principal until previous
credentials and proofs are unusable, dependent state is updated, propagation
has completed, and historical audit attribution remains unambiguous.
