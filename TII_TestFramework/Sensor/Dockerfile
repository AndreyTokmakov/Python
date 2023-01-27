# 182 MB
# FROM python:3-slim

# 103 Mb
FROM python:alpine3.17

# RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" > /log
# RUN echo "Running apt-get update && upgrade"

# RUN apt-get update && apt-get upgrade -y
RUN pip install sqlalchemy sqlalchemy_utils flask

COPY . /sensor
WORKDIR /sensor

ENTRYPOINT ["python", "main.py"]