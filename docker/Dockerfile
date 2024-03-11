FROM alpine:3.19

LABEL maintainer "contact---stalkphish.com"

ENV INITSYSTEM=on

# install packages
RUN apk --no-cache add --update \
py3-lxml \
py3-pip \
git \
python3 \
openrc \
sqlite \
supervisor \
tor

# Clone the project files into the docker container and install it
COPY / /opt/StalkPhish

# Activate python virtual environment
RUN python3 -m venv /opt/venv

WORKDIR /opt/StalkPhish/
RUN /opt/venv/bin/python3 -m pip install --upgrade pip
RUN /opt/venv/bin/pip install -r requirements.txt

# create directories to share
RUN mkdir /opt/StalkPhish/stalkphish/log
RUN mkdir /opt/StalkPhish/stalkphish/dl
RUN mkdir /opt/StalkPhish/stalkphish/db

# Add custom supervisor config
COPY docker/supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord"; "-c"; "/etc/supervisor/conf.d/supervisord.conf"]

# Make some clean
RUN rm -rf /var/cache/apk/*
