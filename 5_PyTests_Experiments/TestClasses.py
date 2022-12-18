# content of test_class.py
class TestClass:
    '''
    def __init__(self):
        pass
    '''

    def setup_module(self, module):
        print("*** Setup ***")

    def test_one(self):
        self.text = 'TEST'
        assert "T" in self.text


    def test_two(self):
        self.text = 'TEST'
        assert "E" in self.text
