
# ----------------------------- 2.1.0 ------------------------------------------------------


docker run --name influxdb -p 8086:8086 influxdb:2.1.0


# http://0.0.0.0:8086



# ----------------------------- 1.8 ------------------------------------------------------

# https://thedatafrog.com/en/articles/docker-influxdb-grafana/


> docker run -d -p 8086:8086 --name influxdb_1.8 influxdb:1.8


# Connect to running container:

> docker exec -it influxdb_1.8 influx




> create database testdb
> show databases
name: databases
name
----
_internal
testdb
> use testdb
Using database testdb




> insert sensor1 x=1,y=2



> select * from sensor1
name: sensor1
time                x y
----                - -
1567156729790701428 1 2