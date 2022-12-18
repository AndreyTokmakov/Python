
import sys  # TODO: Remove it
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

import time
from modules.Service import IService
from modules.Sensor import Sensor
from modules.ServicesPool import ServicesPool


class NetworkMonitor(IService):
    def handler(self) -> bool:
        for i in range(3):
            print(f'{self}: {i}')
            time.sleep(0.5)
        return True


class FilesystemMonitor(IService):
    def handler(self) -> bool:
        for i in range(3):
            print(f'{self}: {i}')
            time.sleep(0.5)
        return True


class DummyService(IService):
    def handler(self) -> bool:
        # print(f'{self}: Created')
        return True


class Tests:

    @staticmethod
    def add_services_tests():
        sensor: Sensor = Sensor()

        print(len(sensor.services_pool.services))

        srv1, srv2 = NetworkMonitor(), FilesystemMonitor()
        srv1.start()
        srv2.start()

        srv1.wait()
        srv2.wait()

        print(len(sensor.services_pool.services))

    @staticmethod
    def check_instances_IDs():
        sensor: Sensor = Sensor()
        pool: ServicesPool = ServicesPool()

        print(sensor.services_pool, f'id: {id(sensor.services_pool)}')
        print(sensor.services_pool.services, f'id: {id(sensor.services_pool.services)}')

        print(pool, f'id: {id(pool)}')
        print(pool.services, f'id: {id(pool.services)}')

    @staticmethod
    def check_instances_IDs2():

        dummy = DummyService()
        dummy.start()
        sensor: Sensor = Sensor()
        pool: ServicesPool = ServicesPool()

        print(sensor.services_pool, f'id: {id(sensor.services_pool)}')
        print(sensor.services_pool.services, f'id: {id(sensor.services_pool.services)}')

        print(pool, f'pool id: {id(pool)}')
        print(pool.services, f'id: {id(pool.services)}')

        # print(dummy.pool, f'pool id: {id(dummy.pool)}')
        # print(dummy.pool.services, f'id: {id(dummy.pool.services)}')


    @staticmethod
    def check_sensor_is_single_instance():
        s1, s2 = Sensor(), Sensor()

        print(s1 == s2)
        print(s1 is s2)





if __name__ == '__main__':
    # Tests.add_services_tests()
    # Tests.check_instances_IDs()
    Tests.check_instances_IDs2()
    # Tests.check_sensor_is_single_instance()
