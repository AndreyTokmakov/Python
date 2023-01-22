class Holder(object):

    def __getattr__(self, name: str):
        print(f'{self.__class__.__name__}::__getattr__() method called')
        setattr(self, name, None)
        return self.__dict__[name]


if __name__ == "__main__":
    holder: Holder = Holder()

    value = holder.value
    description = holder.description

    holder.nodes = []
    nodes = holder.nodes

    print(value, description, nodes)

    holder.nodes.append("One")

    print(value, description, nodes)
