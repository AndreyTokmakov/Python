FROM python:3-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install nano net-tools iw -y

RUN pip install scapy

COPY . /wifi_tests
WORKDIR /wifi_tests
