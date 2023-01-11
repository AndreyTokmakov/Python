
config = {
    "name": 'src1',
    "url": None,
    "deps_file": 'DEPS',
    "managed": False,
    "custom_deps": {},
    "custom_vars": {
        "checkout_pgo_profiles": True,
    },
}


def create_test(*cfg):
    return 'solutions = {}'.format(repr(list(cfg)))


if __name__ == '__main__':
    print(create_test(config))
