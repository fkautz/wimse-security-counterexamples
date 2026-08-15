import unittest

import issuer_origin_binding_counterexample as counterexample


class IssuerOriginBindingCounterexampleTest(unittest.TestCase):
    def test_cross_scheme_origin_is_distinct(self) -> None:
        credential = counterexample.CROSS_SCHEME_CREDENTIAL
        self.assertEqual(
            counterexample.origin_of(credential.subject),
            counterexample.Origin("wimse", "trust.example"),
        )
        self.assertNotIn(
            counterexample.origin_of(credential.subject),
            counterexample.AUTHORIZED_ORIGINS_BY_ISSUER[credential.issuer],
        )

    def test_weak_policy_accepts_both_unauthorized_origins(self) -> None:
        for credential in (
            counterexample.CROSS_SCHEME_CREDENTIAL,
            counterexample.CROSS_AUTHORITY_CREDENTIAL,
        ):
            with self.subTest(credential=credential):
                self.assertTrue(credential.signature_valid)
                self.assertTrue(counterexample.issuer_accepted(credential))
                self.assertTrue(counterexample.authority_trusted(credential))
                self.assertTrue(counterexample.weak_policy_allows(credential))

    def test_exact_origin_binding_rejects_both_attacks(self) -> None:
        for credential in (
            counterexample.CROSS_SCHEME_CREDENTIAL,
            counterexample.CROSS_AUTHORITY_CREDENTIAL,
        ):
            with self.subTest(credential=credential):
                self.assertFalse(
                    counterexample.issuer_authorized_for_subject_origin(credential)
                )
                self.assertFalse(counterexample.strict_policy_allows(credential))

    def test_authorized_issuer_control_is_accepted(self) -> None:
        credential = counterexample.AUTHORIZED_CONTROL_CREDENTIAL
        self.assertTrue(
            counterexample.issuer_authorized_for_subject_origin(credential)
        )
        self.assertTrue(counterexample.strict_policy_allows(credential))


if __name__ == "__main__":
    unittest.main()
