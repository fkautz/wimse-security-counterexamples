# Hierarchical matching

These counterexamples demonstrate authorization failures caused by treating a
textual URI or path prefix as a workload hierarchy.

## Assumptions

Credential validation has succeeded and hierarchical authorization is enabled
by policy. The failure occurs when the consumer applies the policy without
enforcing the exact origin, validated representation, and complete path-segment
boundaries.

## Counterexamples

### Sibling suffix

Policy root:

```text
wimse://trust.example/service/pay
```

Credential subject:

```text
wimse://trust.example/service/payroll-attacker
```

The subject has the authorized text as a prefix but is not a descendant of the
`pay` path segment.

### Dot-segment escape

Policy root:

```text
wimse://trust.example/service/pay
```

Credential subject:

```text
wimse://trust.example/service/pay/../admin
```

A raw prefix check returns `ALLOW`. Removing the dot segment moves the subject
to `/service/admin`, outside the authorized hierarchy.

### Encoded dot-segment escape

Credential subject:

```text
wimse://trust.example/service/pay/%2e%2e/admin
```

A raw prefix check returns `ALLOW`. Percent-decoding followed by dot-segment
normalization again moves the subject outside the authorized hierarchy.

### Origin substitution

Policy root:

```text
wimse://trust.example/service/pay
```

Credential subject:

```text
wimse://attacker.example/service/pay/worker
```

A path-only prefix check returns `ALLOW` even though the subject belongs to a
different origin.

### Empty and root policies

An empty or root path has no parsed path segments. The empty sequence is a
prefix of every path sequence unless the implementation explicitly fails
closed:

| Policy | Policy segments | Presented segments | Fail-open default (incorrect) | Fail-closed default (correct) |
| --- | --- | --- | --- | --- |
| `wimse://trust.example` | `[]` | `["service", "pay", "worker"]` | `ALLOW` | `DENY` |
| `wimse://trust.example/` | `[]` | `["service", "pay", "worker"]` | `ALLOW` | `DENY` |

An explicitly configured origin-wide grant may return `ALLOW`. Without that
explicit grant, `DENY` is correct.

## Run

```sh
python3 hierarchical_matching_counterexample.py
```

Expected output:

```text
sibling_suffix.credential_valid: true
sibling_suffix.policy_enabled: true
sibling_suffix.same_origin: true
sibling_suffix.weak_policy: ALLOW
sibling_suffix.strict_policy: DENY
dot_segment_escape.credential_valid: true
dot_segment_escape.policy_enabled: true
dot_segment_escape.same_origin: true
dot_segment_escape.weak_policy: ALLOW
dot_segment_escape.strict_policy: DENY
encoded_dot_segment_escape.credential_valid: true
encoded_dot_segment_escape.policy_enabled: true
encoded_dot_segment_escape.same_origin: true
encoded_dot_segment_escape.weak_policy: ALLOW
encoded_dot_segment_escape.strict_policy: DENY
origin_substitution.credential_valid: true
origin_substitution.policy_enabled: true
origin_substitution.same_origin: false
origin_substitution.weak_policy: ALLOW
origin_substitution.strict_policy: DENY
empty_path.fail_open_policy: ALLOW
empty_path.fail_closed_default: DENY
empty_path.explicit_originwide: ALLOW
root_path.fail_open_policy: ALLOW
root_path.fail_closed_default: DENY
root_path.explicit_originwide: ALLOW
authorized_descendant.strict_policy: ALLOW
disabled_policy.strict_policy: DENY
security_result: raw prefix policies granted privileges outside the configured hierarchy
```

Run the regression tests:

```sh
python3 -m unittest -v test_hierarchical_matching_counterexample.py
```

## Risk

A valid credential for a sibling workload, a normalized path outside the
authorized subtree, or a different origin can receive hierarchical privileges.
The attack does not require credential forgery or signing-key compromise.

This is the URI equivalent of granting filesystem access with a character
prefix. `/team/pay` is a prefix of `/team/payroll`, but `payroll` is not inside
the `pay` directory.

## Required rule

Non-exact matching is disabled by default. An enabled policy is bound to one
exact `(scheme, authority)` origin and matches validated path segments rather
than raw text. Ambiguous encoded or dot-segment forms are rejected before the
authorization decision.
