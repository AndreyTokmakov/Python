from datetime import datetime

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

'''
# admin
# qwerty12345

# https://thenewstack.io/getting-started-with-python-and-influxdb/
'''


class AuthData(object):
    # You can generate an API token from the "API Tokens Tab" in the UI
    # token = "dKyzcs3TqAQK_elYNq2i19e7Q3xEg5lo4LB5jv33LufmwtmFNk2hfMLYblzoZ48fsEm9YYRYv7yUK1DFSkjJhQ=="
    token = "my-super-secret-auth-token"

    organization = "test_organization"

    bucket = "my_bucket"


def init_client_test():
    with InfluxDBClient(url="http://0.0.0.0:8086",
                        token=AuthData.token,
                        org=AuthData.organization) as client:
        print(client)


def write_test_1():
    with InfluxDBClient(url="http://0.0.0.0:8086",
                        token=AuthData.token,
                        org=AuthData.organization) as client:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        data = "mem,host=host1 used_percent=23.43234543"
        write_api.write(AuthData.bucket, AuthData.organization, data)


def write_test_2():
    with InfluxDBClient(url="http://0.0.0.0:8086",
                        token=AuthData.token,
                        org=AuthData.organization) as client:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        point = Point("mem_test").tag("host", "host1").field("used_percent", 23.45) \
            .time(datetime.utcnow(), WritePrecision.NS)

        write_api.write(AuthData.bucket, AuthData.organization, point)


def query():
    with InfluxDBClient(url="http://0.0.0.0:8086",
                        token=AuthData.token,
                        org=AuthData.organization) as client:
        query = f'from(bucket: "{AuthData.bucket}") |> range(start: -1h)'
        tables = client.query_api().query(query, org=AuthData.organization)
        for table in tables:
            for record in table.records:
                print(record)


class Influx_1_8_Tests(object):

    @staticmethod
    def influx_1_8_Tests():
        with InfluxDBClient(url="http://0.0.0.0:8086",
                            username='admin',
                            password='admin123') as client:
            write_api = client.write_api(write_options=SYNCHRONOUS)
            line = 'power_info,sensor=motor1 power_in=123,power_out=348'
            write_api.write([line], {'db': 'energy'}, 204, 'line')

            # quer  y_api = client.query_api()
            # result = query_api.query('SELECT * FROM "power_info"')

    @staticmethod
    def experiments():
        with InfluxDBClient(url="http://0.0.0.0:8086",
                            username='admin',
                            password='admin123') as client:
            client.create_database('database_name')
            print(client.get_list_database())


'''
dbClient = InfluxDBClient('localhost', 8086, 'root', 'root', 'AccessHistory')

# Write the time series data points into database - user login details
dbClient.create_database('AccessHistory')
dbClient.write_points(loginEvents)

'''

'''
def write_test():

    w_json = [{
        "measurement": 'table_name',
        "time": now_time,
        "tags": {
            'name': 'first name',
            'categories': 'Types of'
        },
        "fields": {
            'price': "price",
            'unit': "unit",
        }
    }]

    with InfluxDBClient(url="http://0.0.0.0:8086",
                        token=AuthData.token,
                        org=AuthData.organization) as client:
        write_api = client.write_api(write_options=SYNCHRONOUS)
        client.write_points(w_json)

'''

if __name__ == '__main__':
    # init_client_test()

    # write_test_1()
    write_test_2()

    # query()




    # Influx_1_8_Tests.influx_1_8_Tests()
    # Influx_1_8_Tests.experiments()
