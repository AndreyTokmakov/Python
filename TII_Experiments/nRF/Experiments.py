
import pynrfjprog
from pynrfjprog import LowLevel

'''
def test_api():
    with LowLevel.API('NRF52') as api:
        api.enum_emu_snr()
        api.connect_to_emu_without_snr()
        api.erase_all()
        api.write_u32(ADDRESS, DATA, IS_FLASH)
        api.disconnect_from_emu()
'''


def check_versions():
    with LowLevel.API('NRF52') as api:
        print("Version: ", api.dll_version())

        print()  # nrfjprog --ids
        print(api.enum_emu_snr())

        print()
        print(api.enum_emu_con_info())

        print()
        print(api.is_connected_to_emu())

        print()
        print(api.read_device_info())


if __name__ == "__main__":
    check_versions()
