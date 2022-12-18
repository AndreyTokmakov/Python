import pytest

from TreatmentQuality.utils.Utilities import Utilities


@pytest.mark.parametrize("pt1, pt2, slope, intercept", [
                         ([0, 0, 0], [1, 1, 1], 1.0, 0.0),
                         ([3, 5, 0], [1, 9, 0], -2.0, 11.0)])
def test_multiplication_11(pt1, pt2, slope, intercept):
    s, i = Utilities.get_line_coefficients(pt1, pt2)
    assert s == slope, "Wrong slope value"
    assert i == intercept, "Wrong intercept value"
