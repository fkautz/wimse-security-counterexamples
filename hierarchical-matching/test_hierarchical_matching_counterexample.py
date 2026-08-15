import unittest

import hierarchical_matching_counterexample as counterexample


class HierarchicalMatchingCounterexampleTest(unittest.TestCase):
    def test_weak_policies_allow_all_attacks(self) -> None:
        for case in counterexample.ATTACK_CASES:
            with self.subTest(case=case.name):
                self.assertTrue(case.credential_valid)
                self.assertTrue(case.policy.enabled)
                self.assertTrue(counterexample.weak_policy_allows(case))

    def test_strict_policy_rejects_all_attacks(self) -> None:
        for case in counterexample.ATTACK_CASES:
            with self.subTest(case=case.name):
                self.assertFalse(
                    counterexample.strict_policy_allows(case)
                )

    def test_sibling_suffix_is_not_a_path_descendant(self) -> None:
        root = counterexample.validated_path_segments(counterexample.POLICY_ROOT)
        sibling = counterexample.validated_path_segments(
            counterexample.SIBLING_SUFFIX
        )
        self.assertIsNotNone(root)
        self.assertIsNotNone(sibling)
        self.assertNotEqual(sibling[: len(root)], root)

    def test_dot_and_encoded_forms_fail_validation(self) -> None:
        for subject in (
            counterexample.DOT_SEGMENT_ESCAPE,
            counterexample.ENCODED_DOT_SEGMENT_ESCAPE,
        ):
            with self.subTest(subject=subject):
                self.assertIsNone(
                    counterexample.validated_path_segments(subject)
                )

    def test_origin_substitution_has_different_origin(self) -> None:
        self.assertFalse(
            counterexample.same_origin(
                counterexample.POLICY_ROOT,
                counterexample.ORIGIN_SUBSTITUTION,
            )
        )

    def test_authorized_descendant_is_allowed(self) -> None:
        self.assertTrue(
            counterexample.strict_segment_policy_allows(
                counterexample.POLICY,
                counterexample.AUTHORIZED_DESCENDANT,
            )
        )

    def test_disabled_policy_is_denied(self) -> None:
        disabled = counterexample.HierarchicalPolicy(
            counterexample.POLICY_ROOT,
            enabled=False,
        )
        self.assertFalse(
            counterexample.strict_segment_policy_allows(
                disabled,
                counterexample.AUTHORIZED_DESCENDANT,
            )
        )

    def test_origin_wide_policy_requires_explicit_grant(self) -> None:
        implicit = counterexample.HierarchicalPolicy("wimse://trust.example/")
        explicit = counterexample.HierarchicalPolicy(
            "wimse://trust.example/",
            allow_entire_origin=True,
        )
        self.assertFalse(
            counterexample.strict_segment_policy_allows(
                implicit,
                counterexample.AUTHORIZED_DESCENDANT,
            )
        )
        self.assertTrue(
            counterexample.strict_segment_policy_allows(
                explicit,
                counterexample.AUTHORIZED_DESCENDANT,
            )
        )


if __name__ == "__main__":
    unittest.main()
