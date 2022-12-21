FROM ubuntu:latest

RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" > /log
RUN echo "Running apt-get update && upgrade"

RUN apt-get update && apt-get upgrade -y
RUN apt-get install python3 python3-pip net-tools nano -y

RUN pip install sqlalchemy flask

COPY . /sensor
WORKDIR /sensor

RUN echo "*** Done ****"
