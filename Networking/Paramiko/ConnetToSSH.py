
import paramiko

def connect_test():
    host, login, password = '95.163.241.50', 'admin', 'ziudjaga'
    cmd: str = "ps axf"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host,
                   username=login,
                   password=password,
                   port=22,
                   look_for_keys=False,
                   allow_agent=False)
    stdin, stdout, stderr = client.exec_command(cmd)
    data = stdout.read() + stderr.read()
    client.close()

    print(data)


if __name__ == '__main__':
    connect_test()