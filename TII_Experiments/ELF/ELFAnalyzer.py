import lief

FILE: str = '/home/andtokm/DiskS/Unikie/TII/contiki-ng-dcube/examples/dcube-nullnet/build/nrf52840/dk/node.elf'


def all_data():
    elf_object = lief.parse(FILE)
    print(elf_object)


def headers():
    elf_object = lief.parse(FILE)
    print(elf_object.header)


def segments():
    elf_object = lief.parse(FILE)
    for seg in elf_object.segments:
        print(seg)


def static_symbols():
    elf_object = lief.parse(FILE)
    for symbol in elf_object.static_symbols:
        # if "customConfigSection" in str(symbol):
        print(symbol)


def print_sections():
    elf_object = lief.parse(FILE)
    for section in elf_object.sections:
        print('Section {name} - size: {size} bytes'.format(name=section.name, size=section.size))


if __name__ == '__main__':
    all_data()
    # headers()
    # segments()
    # static_symbols()
    # print_sections()
    pass
