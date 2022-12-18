'''
Created on Dec 2, 2020
@author: AndTokm
'''

gclient_config = {
    "name"        : 'src',
    "url"         : None,
    "deps_file"   : 'DEPS',
    "managed"     : False,
    "custom_deps" : {},
    "custom_vars" : {
        "checkout_pgo_profiles": True,
    },
}

def test(*config):
    return 'solutions = {}'.format(repr(list(config)))

if __name__ == '__main__':
    print(test(gclient_config))