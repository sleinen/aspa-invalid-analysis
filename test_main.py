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
