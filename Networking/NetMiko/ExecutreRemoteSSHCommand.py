
# import paramiko, getpass, time
from netmiko import ConnectHandler


# https://github.com/ktbyers/netmiko/blob/develop/EXAMPLES.md

if __name__ == '__main__':
    config = {'device_type': 'linux', 'host': '95.163.241.50','username': 'ziudjaga', 'password': 'ziudjaga'}
    net_connect: ConnectHandler = ConnectHandler(**config)

    print(1)