FROM ubuntu:latest

RUN apt-get -y update && apt-get install -y curl software-properties-common apt-transport-https ca-certificates && \
echo "deb https://download.gocd.org /" | tee /etc/apt/sources.list.d/gocd.list && \
curl https://download.gocd.org/GOCD-GPG-KEY.asc | apt-key add - && add-apt-repository ppa:openjdk-r/ppa && \
apt-get update && apt-get install -y openjdk-8-jre openjdk-8-jdk && \
apt-get install -y go-server go-agent

RUN apt-get install -y git zip unzip

RUN curl -L -o /usr/local/bin/grafeas "https://github.com/kashishm/spike/releases/download/v0.0.1/grafeas" && \
curl -L -o /usr/local/bin/gServer https://github.com/kashishm/spike/releases/download/v0.0.1/main

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
apt-get update && apt-get install -y docker.io

RUN cd /var/lib/ && \
curl -L -o dependency-check.zip http://dl.bintray.com/jeremy-long/owasp/dependency-check-3.1.1-release.zip && \
unzip dependency-check.zip && chmod -R 777 dependency-check

COPY cruise-config.xml /etc/go/cruise-config.xml
COPY B943544E.asc /var/lib/B943544E.asc

RUN chmod 777 /etc/go/cruise-config.xml /var/lib/B943544E.asc && chmod +x /usr/local/bin/grafeas /usr/local/bin/gServer

RUN apt-get install -y python-pip python-dev build-essential && pip install --upgrade pip && pip install safety

CMD chmod 777 /var/run/docker.sock && /etc/init.d/go-server start && /etc/init.d/go-agent start && \
su - go -c "gpg --import /var/lib/B943544E.asc" && gServer