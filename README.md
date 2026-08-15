# WIMSE Security Counterexamples

Minimal, executable counterexamples for security and interoperability issues
in WIMSE Internet-Drafts.

This is an independent repository. It is not an official IETF or WIMSE Working
Group repository.

## Counterexamples

| Directory | Issue | Weak result | Strict result |
| --- | --- | --- | --- |
| [`canonicalization`](canonicalization/) | Inconsistent URI equality merges issuer-distinct workload identities | `ALLOW` | `DENY` |

## Design

Each counterexample:

- is self-contained and deterministic;
- uses only the language standard library where practical;
- states its security assumptions;
- prints the vulnerable and strict outcomes;
- includes regression tests; and
- identifies the normative rule that blocks the vulnerable outcome.

Some examples begin after successful credential verification. This is
intentional when the failure occurs during identifier interpretation,
endpoint selection, or authorization rather than cryptographic validation.

## Run all tests

```sh
python3 canonicalization/canonicalization_counterexample.py
cd canonicalization
python3 -m unittest -v test_canonicalization_counterexample.py
```

## Related specification

- [WIMSE Workload Identifier](https://datatracker.ietf.org/doc/draft-ietf-wimse-identifier/)

## License

BSD 2-Clause. See [`LICENSE`](LICENSE).
