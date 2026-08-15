# Issuer-to-origin binding

These counterexamples demonstrate authorization failures caused by accepting a
credential issuer without verifying that it is authorized for the exact
Workload Identifier Origin asserted by the credential.

## Assumptions

The credential signature is valid. The consumer accepts the signing issuer and
trusts the authority string in the credential subject. The failure occurs
because those independent checks are not joined into an issuer-to-origin
binding that includes both the URI scheme and authority.

## Counterexamples

### Same authority, different scheme

The issuer is authorized for:

```text
spiffe://trust.example
```

It signs a credential asserting this privileged subject:

```text
wimse://trust.example/service/payment
```

A consumer that checks only whether the issuer is accepted and
`trust.example` is trusted returns `ALLOW`. The issuer was never authorized
for the `wimse://trust.example` origin.

### Same scheme, different authority

The issuer is authorized for:

```text
wimse://dev.example
```

It signs a credential asserting this privileged subject:

```text
wimse://prod.example/service/admin
```

A consumer with separate global issuer and trusted-authority allowlists
returns `ALLOW`. The issuer was never authorized for the
`wimse://prod.example` origin.

## Run

```sh
python3 issuer_origin_binding_counterexample.py
```

Expected output:

```text
cross_scheme.signature_valid: true
cross_scheme.issuer_accepted: true
cross_scheme.authority_trusted: true
cross_scheme.issuer_origin_authorized: false
cross_scheme.weak_policy: ALLOW
cross_scheme.strict_policy: DENY
cross_authority.signature_valid: true
cross_authority.issuer_accepted: true
cross_authority.authority_trusted: true
cross_authority.issuer_origin_authorized: false
cross_authority.weak_policy: ALLOW
cross_authority.strict_policy: DENY
authorized_control.strict_policy: ALLOW
security_result: accepted issuers asserted privileged identities outside their authorized origins
```

Run the regression tests:

```sh
python3 -m unittest -v test_issuer_origin_binding_counterexample.py
```

## Risk

A valid signature proves which key signed a credential. It does not prove that
the signer is authorized to create identities in every namespace. Without an
exact origin binding, an accepted issuer can assert a privileged identity in a
different scheme or authority. The attack does not require forgery or
compromise of a signing key authorized for the target origin.

This resembles a certification authority being trusted for one namespace and
then being treated as trusted for every other name system containing the same
text.

## Required rule

Consumers bind each exact `(scheme, authority)` origin to the issuers and trust
material authorized to assert identifiers in that origin. An unknown scheme,
an unconfigured issuer-to-origin relation, or a missing binding fails closed.
