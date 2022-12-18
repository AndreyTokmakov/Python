import sys

sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

from modules.Service import IService


class DummyService(IService):
    def handler(self) -> bool:
        # print(f'{self}: Created')
        return True
