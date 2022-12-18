
import pexpect

if __name__ == '__main__':
    child = pexpect.spawn('ssh root@192.168.1.6')

    child.expect('Password:')
    print(child.before)

    child.sendline('root')
    print(child.before)

    child.expect('root@br_hardened:')
    print(child.before)

    child.sendline('ps axf')
    print(child.before)

    child.sendline('exit')