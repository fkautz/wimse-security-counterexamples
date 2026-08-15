# Canonicalization and equality

This counterexample demonstrates an authorization collision caused by
inconsistent Workload Identifier equality.

## Assumption

Credential signature validation has already succeeded. The failure occurs when
the consumer converts the validated credential subject into an authorization
key.

## Subjects

The issuer treats these strings as distinct:

```text
wimse://trust.example/service/payment
wimse://trust.example/service/%70ayment
```

A consumer that decodes percent-encoded unreserved characters reduces both to:

```text
wimse://trust.example/service/payment
```

The weak policy therefore grants the second principal privileges assigned to
the first principal.

## Run

```sh
python3 canonicalization_counterexample.py
```

Expected output:

```text
issuer_distinct: true
weak_normalized_equal: true
weak_policy: ALLOW
strict_policy: DENY
security_result: non-canonical identity received canonical identity privileges
```

Run the regression tests:

```sh
python3 -m unittest -v test_canonicalization_counterexample.py
```

## Risk

The attack does not require credential forgery or signing-key compromise. A
valid credential containing an alternate URI representation can receive
another workload's authorization. The collision can also affect mapping,
caching, revocation, and audit attribution.

## Required rule

Issuers emit one canonical representation. Consumers reject non-canonical
subjects before authorization. All security-sensitive components compare the
complete validated canonical representation byte for byte.
