import unittest

import canonicalization_counterexample as counterexample


class CanonicalizationCounterexampleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.credential = counterexample.ValidatedCredential(
            principal="reporting",
            subject=counterexample.NON_CANONICAL_SUBJECT,
        )

    def test_weak_comparison_merges_issuer_distinct_subjects(self) -> None:
        self.assertNotEqual(
            counterexample.CANONICAL_SUBJECT,
            counterexample.NON_CANONICAL_SUBJECT,
        )
        self.assertEqual(
            counterexample.weak_identity_key(counterexample.CANONICAL_SUBJECT),
            counterexample.weak_identity_key(counterexample.NON_CANONICAL_SUBJECT),
        )
        self.assertTrue(counterexample.weak_policy_allows(self.credential))

    def test_canonical_profile_blocks_collision(self) -> None:
        self.assertTrue(
            counterexample.is_canonical_wimse_identifier(
                counterexample.CANONICAL_SUBJECT
            )
        )
        self.assertFalse(
            counterexample.is_canonical_wimse_identifier(
                counterexample.NON_CANONICAL_SUBJECT
            )
        )
        self.assertFalse(counterexample.strict_policy_allows(self.credential))


if __name__ == "__main__":
    unittest.main()
