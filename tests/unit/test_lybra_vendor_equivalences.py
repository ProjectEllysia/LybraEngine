"""El feed de vendors equivalentes está bien formado y el helper lo aplica."""

import pytest

from lybra import equivalent_vendors
from lybra.core.vulndata import load_vendor_equivalences

pytestmark = pytest.mark.unit


def test_every_group_has_at_least_two_distinct_vendors():
    groups = load_vendor_equivalences()

    assert groups
    for product, vendors in groups.items():
        assert isinstance(product, str) and product
        assert len(vendors) >= 2, product
        assert len(set(vendors)) == len(vendors), product
        assert all(isinstance(vendor, str) and vendor for vendor in vendors), product


def test_the_given_vendor_comes_first_and_outsiders_get_only_themselves():
    assert equivalent_vendors("f5", "nginx") == ("f5", "nginx")
    assert equivalent_vendors("nginx", "nginx") == ("nginx", "f5")
    assert equivalent_vendors("other", "nginx") == ("other",)
    assert equivalent_vendors("f5", "unknown_product") == ("f5",)
