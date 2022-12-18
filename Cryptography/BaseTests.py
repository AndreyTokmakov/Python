import gnupg


def create_gpg():
    gpg = gnupg.GPG(gnupghome='/home/andtokm/DiskS/ProjectsUbuntu/Python/Cryptography')
    gpg.encoding = 'utf-8'


def generate_keys():
    gpg = gnupg.GPG(gnupghome='/home/andtokm/DiskS/ProjectsUbuntu/Python/Cryptography')
    gpg.encoding = 'utf-8'

    input_data = gpg.gen_key_input(name_real='provServer',
                                   passphrase='',
                                   no_protection=True,
                                   name_email='provServer',
                                   expire_date='1m')
    key = gpg.gen_key(input_data)
    fingerprint = key.fingerprint

    print('------------------------------ Key -------------------------------')
    print(key)

    print('------------------------------- fingerprint -------------------------------')
    print(fingerprint)

    print('-------------------------------------------------------------------')
    ID = input_data.split('Name-Real: ')[1].split('\n')[0]
    if 'node' in ID:
        ID = ID.split('node')[1]
        print(f'Key pair generated with fingerprint {fingerprint}')


def generate_keys_1():
    gpg = gnupg.GPG(gnupghome='/home/andtokm/DiskS/ProjectsUbuntu/Python/Cryptography')
    gpg.encoding = 'utf-8'

    alice = {'name_real': 'Alice',
             'name_email': 'alice@inter.net',
             'expire_date': '2023-04-01',
             'key_type': 'RSA',
             'key_length': 1024,
             'key_usage': '',
             'subkey_type': 'RSA',
             'subkey_length': 1024,
             'subkey_usage': 'encrypt,sign,auth',
             'passphrase': 'mypass'}

    input_data = gpg.gen_key_input(**alice)

    key = gpg.gen_key(input_data)
    fingerprint = key.fingerprint

    print('------------------------------- key -------------------------------')
    print(key)

    print('------------------------------- Key -------------------------------')
    print(fingerprint)


if __name__ == '__main__':
    print("Cryptography experiments....")

    # create_gpg()
    # generate_keys()
    generate_keys_1()
