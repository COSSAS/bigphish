FROM ubuntu:20.04

WORKDIR /crawler

ARG DEBIAN_FRONTEND=noninteractive
ENV PYCURL_SSL_LIBRARY=openssl

# Install OS dependencies
RUN apt-get -y update && \
    apt-get install -y \
    whois \
    firefox-geckodriver \
    libcurl4-openssl-dev \
    libssl-dev \
    tzdata \
    python3 \
    python3-pip

# Install Python requirements
COPY requirements.txt requirements.txt
RUN python3 -m pip install --upgrade pip==23.3.2 && pip3 install -r requirements.txt

# Copy all necessary files and scripts
COPY *.py *.json *.txt *.sh /crawler/

# Start crawler module
RUN chmod +x run.sh
CMD ./run.sh
