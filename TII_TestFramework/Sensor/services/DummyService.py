import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")


from modules.Service import IService


class DummyService(IService):
    def handler(self) -> bool:
        # print(f'{self}: Created')
        return True
