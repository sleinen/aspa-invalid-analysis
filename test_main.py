import pytest
from main import as_relation

class MockRpkiCache:
    def __init__(self, aspas):
        self.aspas = aspas

def test_as_relation():
    # Both ASes have no ASPA
    rpki_cache = MockRpkiCache(aspas={})
    assert as_relation(1, 2, rpki_cache) == " "

    # AS1 has ASPA, AS2 does not
    rpki_cache = MockRpkiCache(aspas={1: {2}})
    assert as_relation(1, 2, rpki_cache) == " ⇒ "
    rpki_cache = MockRpkiCache(aspas={1: {3}})
    assert as_relation(1, 2, rpki_cache) == " ⇏ "

    # AS2 has ASPA, AS1 does not
    rpki_cache = MockRpkiCache(aspas={2: {1}})
    assert as_relation(1, 2, rpki_cache) == " ⇐ "
    rpki_cache = MockRpkiCache(aspas={2: {3}})
    assert as_relation(1, 2, rpki_cache) == " ⇍ "

    # Both ASes have ASPAs
    rpki_cache = MockRpkiCache(aspas={1: {2}, 2: {1}})
    assert as_relation(1, 2, rpki_cache) == " ⇔ "
    rpki_cache = MockRpkiCache(aspas={1: {3}, 2: {4}})
    assert as_relation(1, 2, rpki_cache) == " ⇎ "
    rpki_cache = MockRpkiCache(aspas={1: {2}, 2: {3}})
    assert as_relation(1, 2, rpki_cache) == " ⇒⇍ "
    rpki_cache = MockRpkiCache(aspas={1: {3}, 2: {1}})
    assert as_relation(1, 2, rpki_cache) == " ⇏⇐ "

    # AS1 and AS2 are the same
    rpki_cache = MockRpkiCache(aspas={})
    assert as_relation(1, 1, rpki_cache) == " "

def test_check_aspa():
    from main import check_aspa, ASPA_UNKNOWN, ASPA_VALID, ASPA_INVALID

    # Mock RpkiCache
    class MockRpkiCache:
        def __init__(self, own_as, aspas):
            self.own_as = own_as
            self.aspas = aspas

    # Scenario 1: AS Set in path (Invalid)
    # Path: [1, 2, [3, 4], 5]
    rpki = MockRpkiCache(own_as=100, aspas={})
    assert check_aspa([1, 2, [3, 4], 5], rpki) == ASPA_INVALID

    # Scenario 2: Empty path (Invalid)
    assert check_aspa([], rpki) == ASPA_INVALID

    # Scenario 3: Valid Upstream (Customer -> Provider -> ... -> Provider)
    # Receiving AS: 100. Neighbor: 10.
    # Path: [10, 20, 30]. Origin 30.
    # Relationships: 30->20 (P), 20->10 (P). 10 is Peer/Customer of 100?
    # Assume Upstream if Neighbor not in Own ASPA.
    # 10 not in 100's ASPA (100 has no providers). So Upstream.
    # Upstream checks max_up_ramp.
    # Pairs: (30, 20), (20, 10).
    # Need 30->20 P+ (20 in 30's ASPA).
    # Need 20->10 P+ (10 in 20's ASPA).
    aspas = {
        30: {20},
        20: {10},
        # 10 has no ASPA for 100 (irrelevant for Upstream check which ends at N)
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # Compressed Path: 10, 20, 30
    # N=3.
    # I=1: u=30, v=20. auth(30,20) -> Provider+.
    # I=2: u=20, v=10. auth(20,10) -> Provider+.
    # max_up_ramp = 3.
    # min_up_ramp = 3.
    # Upstream check: max_up < 3? No. min_up < 3? No. Valid.
    assert check_aspa([10, 20, 30], rpki) == ASPA_VALID

    # Scenario 4: Invalid Upstream (Leak)
    # Path: [10, 20, 30]. Origin 30.
    # Relationships: 30->20 (P), 20->10 (C).
    # 20->10 means 10 is NOT in 20's ASPA.
    aspas = {
        30: {20},
        20: {40}, # 20's provider is 40, not 10.
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # I=1: 30->20 (P+).
    # I=2: 20->10 (Not P+). max_up_ramp = 2.
    # N=3. max_up_ramp < N (2 < 3). Invalid.
    assert check_aspa([10, 20, 30], rpki) == ASPA_INVALID

    # Scenario 5: Unknown Upstream
    # Path: [10, 20, 30].
    # 30 has no ASPA. 20->10 (P).
    aspas = {
        # 30: No ASPA
        20: {10}
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # I=1: 30->20 (No Attestation).
    # min_up_ramp = 1.
    # max_up_ramp: 30->20 is No Attestation (Not "Not Provider+").
    #   I=2: 20->10 (P+).
    #   max_up_ramp = 3.
    # Check:
    # max_up < 3? No (3).
    # min_up < 3? Yes (1 < 3).
    # Result: Unknown.
    assert check_aspa([10, 20, 30], rpki) == ASPA_UNKNOWN

    # Scenario 6: Valid Downstream (Provider -> Customer)
    # Receiving AS: 100. Neighbor: 10.
    # Neighbor 10 IS in 100's ASPA.
    aspas = {
        100: {10}, # We are Customer of 10.
        10: {20},  # 10 is Customer of 20 (Wait, 10->20 P+).
        20: {30},  # 20 is Customer of 30.
        # Path: 10, 20, 30. Origin 30.
        # 30->20->10 -> 100.
        30: {}, # 30 has ASPA but empty/irrelevant
    }
    # Path: [10, 20, 30].
    # But wait, Downstream allows Down-Ramps.
    # Let's say Path: [10, 20, 40]. Origin 40.
    # 40->20 (P+). 20->10 (P+).
    # Up-Ramp from 40 to 10? No, this is Down-Ramp from Neighbor 10 backwards?
    # Path direction: Origin -> ... -> Neighbor.
    # Path List: [10, 20, 40]. (10 is Neighbor).
    # 40 (Origin) -> 20 -> 10 -> 100 (Us).
    # If 10 is our Provider, we are receiving from Provider.
    # This path 40->20->10 implies 40 is Customer of 20? No.
    # Usually: 40 (Cust) -> 20 (Prov) -> 10 (Prov) -> 100 (Cust).
    # This is valid.
    # 40->20: P+ (20 in 40's ASPA).
    # 20->10: P+ (10 in 20's ASPA).
    # 10->100: P+ (100 in 10's ASPA? No, 100 is Cust of 10. 10 is Prov of 100).
    # Neighbor 10 is in 100's ASPA. Correct.

    # Let's define ASPAs:
    aspas = {
        100: {10}, # 10 is Provider of 100. => Downstream algo.
        40: {20},  # 20 is Provider of 40.
        20: {10},  # 10 is Provider of 20.
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # Path: [10, 20, 40]. N=3.
    # Up-Ramp check (from Origin 40).
    # I=1: u=40, v=20. auth(40, 20) -> P+.
    # I=2: u=20, v=10. auth(20, 10) -> P+.
    # max_up_ramp = 3.
    # min_up_ramp = 3.
    # max_down_ramp logic (from Neighbor 10 backwards).
    # J=3: u=10, v=20. auth(10, 20).
    # 10's ASPA? Not defined in aspas dict (so No Attestation).
    # Wait, if 10 has no ASPA, auth(10, 20) is No Attestation.
    # max_down_ramp: stops at "Not Provider+". No Attestation is NOT "Not Provider+".
    # So max_down_ramp continues.
    # J=2: u=20, v=40. auth(20, 40). 40 in 20's ASPA? No (20:{10}). -> Not Provider+.
    # Stop. max_down_ramp = 3 - 2 + 1 = 2.

    # Check:
    # max_up (3) + max_down (2) = 5 >= 3. Valid.
    assert check_aspa([10, 20, 40], rpki) == ASPA_VALID

    # Scenario 7: Valid Downstream with full Down-Ramp
    # Path: [10, 11, 12]. Origin 12.
    # 12 -> 11 (C->P? No, P->C).
    # Let's say Peer -> Provider -> Customer.
    # Origin 12 is Provider of 11. 11 is Provider of 10. 10 is Provider of 100.
    # Path: 12 -> 11 -> 10 -> 100.
    # This is a full Down-Ramp.
    # 12 has ASPA (doesn't list 11).
    # 11 has ASPA (lists 12? No).
    # Relationships:
    # 10 is Prov of 100 (Downstream algo).
    # 11 is Prov of 10. (10 lists 11).
    # 12 is Prov of 11. (11 lists 12).
    aspas = {
        100: {10},
        10: {11},
        11: {12},
        12: {999},
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    path = [10, 11, 12]
    # Up-Ramp:
    # I=1: 12->11. auth(12, 11). 11 NOT in 12's ASPA. -> Not Provider+.
    # max_up_ramp = 1.

    # Down-Ramp:
    # J=3: 10->11. auth(10, 11) -> P+.
    # J=2: 11->12. auth(11, 12) -> P+.
    # max_down_ramp = 3.

    # Check:
    # max_up (1) + max_down (3) = 4 >= 3. Valid.
    assert check_aspa(path, rpki) == ASPA_VALID

    # Scenario 8: Invalid Downstream (Valley)
    # Path: [10, 20, 30].
    # 10 is Prov of 100.
    # 20 is NOT Prov of 10. (10->20 Not P+).
    # 30 is NOT Prov of 20. (20->30 Not P+).
    # And 20 is NOT Prov of 30 (30->20 Not P+).
    # Basically Peer-Peer-Peer or Cust-Cust-Cust.
    aspas = {
        100: {10},
        10: {99}, # 10 has ASPA, 20 not in it.
        20: {99}, # 20 has ASPA, 10 not in it, 30 not in it.
        30: {99}, # 30 has ASPA, 20 not in it.
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    path = [10, 20, 30]
    # Up-Ramp:
    # I=1: 30->20. Not P+. max_up = 1.

    # Down-Ramp:
    # J=3: 10->20. Not P+. max_down = 1.

    # Check:
    # max_up(1) + max_down(1) = 2 < 3. Invalid.
    assert check_aspa(path, rpki) == ASPA_INVALID

    # Scenario 9: Duplicates
    # Path: [10, 10, 20, 20, 20, 30]. -> [10, 20, 30].
    # Same as Scenario 3.
    aspas = {
        30: {20},
        20: {10},
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    assert check_aspa([10, 10, 20, 20, 20, 30], rpki) == ASPA_VALID

    # Scenario 10: Disjoint Ramps (sum == N) -> Invalid
    # Path: [10, 20]. N=2. Neighbor 10.
    # We are receiving from Neighbor 10.
    # If 10 is our Provider (Downstream).
    # 20 -> 10.
    # 20 is NOT Provider of 10. 10 is NOT Provider of 20.
    # No ASPA between them.
    # But checking max_up and max_down.
    # Up-Ramp: I=1: 20->10. auth(20, 10) -> No Attestation.
    # max_up = 1.
    # Down-Ramp: J=2: 10->20. auth(10, 20) -> No Attestation.
    # max_down = 2 - 2 + 1 = 1.
    # sum = 1 + 1 = 2. N = 2.
    # New check: sum - 1 < N => 2 - 1 < 2 => 1 < 2 => True (Invalid).
    # Old check: sum < N => 2 < 2 => False (Valid).
    # Should be Invalid.
    # Also min check: min_up=1, min_down=1. sum=2.
    # 1 < 2 -> Unknown.
    # Wait.
    # max_up + max_down - 1 < N (Check for Invalid).
    # 1 + 1 - 1 = 1 < 2. Invalid.

    # We need to setup RpkiCache such that it is Downstream.
    # 10 is Provider of 100.
    aspas = {
        100: {10}, # Downstream.
        # No other ASPAs.
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # With No Attestation, max_up stops at "Not Provider+".
    # auth(20, 10) is No Attestation. So loop continues?
    # No. Loop continues if authorized != NOT_PROVIDER_PLUS.
    # So max_up becomes 2 (since loop finishes).
    # Then sum = 2 + ... > N. Valid?

    # We need "Not Provider+" to stop the ramp at 1.
    # So 20 must have ASPA that does NOT include 10.
    # And 10 must have ASPA that does NOT include 20.
    aspas = {
        100: {10},
        20: {99}, # 20->99. 10 not in 20's ASPA.
        10: {99}, # 10->99. 20 not in 10's ASPA.
    }
    rpki = MockRpkiCache(own_as=100, aspas=aspas)
    # Up-Ramp: I=1: 20->10. auth(20, 10) -> Not Provider+. max_up = 1.
    # Down-Ramp: J=2: 10->20. auth(10, 20) -> Not Provider+. max_down = 1.
    # max_up + max_down - 1 = 1.
    # 1 < 2. Invalid.
    assert check_aspa([10, 20], rpki) == ASPA_INVALID
