import pytest


@pytest.fixture()
def resource_setup(request):
    print(" ---- resource_setup -----")

    def resource_teardown():
        print("---- resource_teardown -----")

    request.addfinalizer(resource_teardown)


def test_1_that_needs_resource(resource_setup):
    print("test_1_that_needs_resource")


def test_2_that_does_not():
    print("test_2_that_does_not")


def test_3_that_does_again(resource_setup):
    print("test_3_that_does_again")




class Fruit:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

    def __str__(self):
        return type(self).__name__


@pytest.fixture
def my_fruit():
    return Fruit("apple")


@pytest.fixture
def fruit_basket(my_fruit):
    return [Fruit("banana"), my_fruit]


def test_my_fruit_in_basket(my_fruit, fruit_basket):
    print(my_fruit)
    print(fruit_basket)
    assert my_fruit in fruit_basket