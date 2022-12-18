import pytest


def setup():
    print("*** Setup ***")


def teardown():
    print("*** Teardown ***")


def setup_module(module):
    print("*** setup (Module) ***")


def teardown_module(module):
    print("*** teardown (Module) ***")


def setup_function(function):
    print("*** setup (Function) ***")


def teardown_function(function):
    print("*** teardown (Function) ***")


def test_upper():
    assert 'foo'.upper() == 'FOO'


def test_isupper():
    assert 'FOO'.isupper()


'''
def test_failed_upper():
    assert 'foo'.upper() == 'FOo'
'''
