import unittest
from dataclasses import replace

import identifier_uniqueness_and_reuse_counterexample as counterexample


class IdentifierUniquenessAndReuseCounterexampleTest(unittest.TestCase):
    def test_local_uniqueness_misses_multi_issuer_collision(self) -> None:
        allocations = counterexample.COLLIDING_ALLOCATIONS
        self.assertTrue(counterexample.issuer_local_unique(allocations, "issuer-a"))
        self.assertTrue(counterexample.issuer_local_unique(allocations, "issuer-b"))
        self.assertTrue(counterexample.weak_allocation_accepts(allocations))
        self.assertFalse(counterexample.origin_wide_unique(allocations))
        self.assertFalse(counterexample.strict_allocation_accepts(allocations))

    def test_same_logical_principal_can_share_identifier(self) -> None:
        allocations = counterexample.SHARED_PRINCIPAL_ALLOCATIONS
        self.assertTrue(counterexample.origin_wide_unique(allocations))
        self.assertTrue(counterexample.strict_allocation_accepts(allocations))

    def test_intentional_reuse_does_not_retire_old_credential(self) -> None:
        attempt = counterexample.UNSAFE_REUSE
        self.assertTrue(attempt.intentional)
        self.assertTrue(attempt.previous_credential_valid)
        self.assertTrue(counterexample.weak_reassignment_accepts(attempt))
        self.assertTrue(counterexample.weak_policy_allows_old_principal(attempt))

    def test_strict_reuse_blocks_privilege_inheritance(self) -> None:
        attempt = counterexample.UNSAFE_REUSE
        self.assertFalse(counterexample.strict_reassignment_accepts(attempt))
        self.assertFalse(counterexample.strict_policy_allows_old_principal(attempt))

    def test_safe_reassignment_is_accepted(self) -> None:
        self.assertTrue(
            counterexample.strict_reassignment_accepts(counterexample.SAFE_REUSE)
        )

    def test_same_principal_rotation_is_not_reassignment(self) -> None:
        self.assertTrue(
            counterexample.strict_reassignment_accepts(
                counterexample.SAME_PRINCIPAL_ROTATION
            )
        )

    def test_each_safety_condition_is_required(self) -> None:
        safe = counterexample.SAFE_REUSE
        unsafe_variants = (
            replace(safe, previous_credential_valid=True),
            replace(safe, previous_proof_valid=True),
            replace(safe, authorization_cache_active=True),
            replace(safe, external_mapping_active=True),
            replace(safe, updates_propagated=False),
            replace(safe, audit_attribution_preserved=False),
        )
        for attempt in unsafe_variants:
            with self.subTest(attempt=attempt):
                self.assertFalse(
                    counterexample.strict_reassignment_accepts(attempt)
                )


if __name__ == "__main__":
    unittest.main()
