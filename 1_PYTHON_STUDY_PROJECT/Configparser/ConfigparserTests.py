import configparser

def DB_Config():
    config = configparser.ConfigParser()
    config.read('db.ini')
    
    host = config['mysql']['host']
    user = config['mysql']['user']
    passwd = config['mysql']['passwd']
    db = config['mysql']['db']
    
    print('MySQL configuration:')
    
    print(f'Host: {host}')
    print(f'User: {user}')
    print(f'Password: {passwd}')
    print(f'Database: {db}')
    
    host2 = config['postgresql']['host']
    user2 = config['postgresql']['user']
    passwd2 = config['postgresql']['passwd']
    db2 = config['postgresql']['db']
    
    print('PostgreSQL configuration:')
    
    print(f'Host: {host2}')
    print(f'User: {user2}')
    print(f'Password: {passwd2}')
    print(f'Database: {db2}')

if __name__ == '__main__':
    DB_Config();