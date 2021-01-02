FROM ubuntu:18.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python-pip libmysqlclient-dev python3.7-dev  build-essential libssl-dev libffi-dev python-dev python3-pip mariadb-server mariadb-client

LABEL description="Pensando Tap As A Service"
LABEL version="1.0"
LABEL maintainer="Toby Makepeace"


WORKDIR /app/src

COPY src /app/src

RUN pip3 install -r /app/src/requirements.txt


EXPOSE 5000 

ENTRYPOINT bash /app/src/start.sh 
